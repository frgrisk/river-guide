package cmd

import (
	"context"
	"errors"
	"fmt"
	"sort"

	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"golang.org/x/sync/errgroup"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/smithy-go"
)

type AWSProvider struct {
	svc *ec2.Client
	rds *rds.Client
}

var rdsInstanceStatus = map[string]string{
	"available": "running",
	"starting":  "pending",
	"stopping":  "stopping",
	"stopped":   "stopped",
	"rebooting": "pending",
}

// GetStatus implements CloudProvider.
func (h *AWSProvider) GetStatus() string {
	panic("unimplemented")
}

// GetServerBank queries AWS EC2 instances based on the specified tags.
func (h *AWSProvider) GetServerBank(tags map[string]string) (*ServerBank, error) {
	serverBank := &ServerBank{}

	// Query EC2 instances if EC2 client is available
	servers, err := h.GetEC2Instances(tags)
	if err != nil {
		return nil, fmt.Errorf("failed to get EC2 instances: %v", err)
	}
	if len(servers) > 0 {
		serverBank.Servers = append(serverBank.Servers, servers...)
	}

	// Query RDS instances if RDS client is available
	servers, err = h.GetRDSInstances(tags)
	if err != nil {
		return nil, fmt.Errorf("failed to get RDS instances: %v", err)
	}
	if len(servers) > 0 {
		serverBank.Servers = append(serverBank.Servers, servers...)
	}

	// Sort servers by name
	sort.Slice(serverBank.Servers, func(i, j int) bool {
		return serverBank.Servers[i].Name < serverBank.Servers[j].Name
	})

	return serverBank, nil
}

func (h *AWSProvider) GetEC2Instances(tags map[string]string) ([]*Server, error) {
	// Build the filter for tag-based instance query
	filters := make([]types.Filter, 0, len(tags)+1)
	for key, value := range tags {
		filters = append(filters, types.Filter{
			Name:   aws.String(fmt.Sprintf("tag:%s", key)),
			Values: []string{value},
		})
	}
	filters = append(filters, types.Filter{
		Name: aws.String("instance-state-name"),
		Values: []string{
			string(types.InstanceStateNamePending),
			string(types.InstanceStateNameRunning),
			string(types.InstanceStateNameStopping),
			string(types.InstanceStateNameStopped),
		},
	})

	// Describe EC2 instances with the specified tags
	resp, err := h.svc.DescribeInstances(
		context.TODO(),
		&ec2.DescribeInstancesInput{
			Filters: filters,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to describe instances: %v", err)
	}

	servers := make([]*Server, 0)
	for _, reservation := range resp.Reservations {
		for _, instance := range reservation.Instances {
			server := &Server{
				ID:     instance.InstanceId,
				Status: string(instance.State.Name),
				Type:   EC2,
			}
			for _, tag := range instance.Tags {
				if *tag.Key == "Name" {
					server.Name = *tag.Value
					break
				}
			}
			servers = append(servers, server)
		}
	}

	return servers, nil
}

// GetRDSInstances queries AWS RDS instances based on the specified tags.
func (h *AWSProvider) GetRDSInstances(tags map[string]string) ([]*Server, error) {
	if h.rds == nil {
		return nil, nil
	}
	// Describe all RDS instances
	resp, err := h.rds.DescribeDBInstances(context.TODO(), &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe RDS instances: %v", err)
	}

	// Filter RDS instances based on the specified tags
	servers := make([]*Server, 0)
	for _, instance := range resp.DBInstances {
		if !areTagsMatch(tags, instance.TagList) {
			continue
		}

		if _, ok := rdsInstanceStatus[aws.ToString(instance.DBInstanceStatus)]; !ok {
			continue
		}

		// populate server list
		server := &Server{
			ID:     instance.DBInstanceIdentifier,
			Status: rdsInstanceStatus[aws.ToString(instance.DBInstanceStatus)],
			Type:   RDS,
		}
		for _, tag := range instance.TagList {
			if *tag.Key == "Name" {
				server.Name = *tag.Value
				break
			}
		}
		servers = append(servers, server)

	}
	return servers, nil
}

func areTagsMatch(tags map[string]string, instanceTags []rdstypes.Tag) bool {
	matchedTags := 0
	for _, tag := range instanceTags {
		if value, ok := tags[aws.ToString(tag.Key)]; ok && value == aws.ToString(tag.Value) {
			matchedTags++
		}
	}
	return matchedTags == len(tags)
}

// PowerOnAll powers on all the servers in the bank and updates their statuses.
func (h *AWSProvider) PowerOnAll(sb *ServerBank) error {
	var (
		instanceIDs  []string
		rdsInstances []*Server
		g            errgroup.Group
	)

	for _, server := range sb.Servers {
		if server.Status == string(types.InstanceStateNameStopped) {
			if server.Type == RDS {
				rdsInstances = append(rdsInstances, server)
			} else {
				instanceIDs = append(instanceIDs, *server.ID)
			}
		}
	}

	g.Go(func() error {
		return h.PowerOnEC2Instances(instanceIDs)
	})

	g.Go(func() error {
		return h.PowerOnRDSInstances(rdsInstances)
	})

	return g.Wait()
}

// PowerOnEC2Instances powers on the specified EC2 instances.
func (h *AWSProvider) PowerOnEC2Instances(instanceIDs []string) error {
	if h.svc == nil || len(instanceIDs) == 0 {
		return nil
	}
	// We set DryRun to true to check to see if the instance exists, and we have the
	// necessary permissions to monitor the instance.
	input := &ec2.StartInstancesInput{
		InstanceIds: instanceIDs,
		DryRun:      aws.Bool(true),
	}
	_, err := h.svc.StartInstances(context.TODO(), input)
	// If the error code is `DryRunOperation` it means we have the necessary
	// permissions to Start this instance
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) {
			if ae.ErrorCode() == "DryRunOperation" {
				// Let's now set dry run to be false. This will allow us to start the instances
				input.DryRun = aws.Bool(false)
				_, err = h.svc.StartInstances(context.TODO(), input)
			}
		}
	}
	return err
}

// PowerOnRDSInstances powers on the specified RDS instances.
func (h *AWSProvider) PowerOnRDSInstances(servers []*Server) error {
	if h.rds == nil || len(servers) == 0 {
		return nil
	}
	var g errgroup.Group
	for _, server := range servers {
		s := server
		g.Go(func() error {
			_, err := h.rds.StartDBInstance(context.TODO(), &rds.StartDBInstanceInput{
				DBInstanceIdentifier: s.ID,
			})
			if err != nil {
				return fmt.Errorf("failed to start RDS instance %s: %v", aws.ToString(server.ID), err)
			}
			return nil
		})
	}
	return g.Wait()
}

// PowerOffAll powers off all the servers in the bank and updates their statuses.
func (h *AWSProvider) PowerOffAll(sb *ServerBank) error {
	var (
		instanceIDs  []string
		rdsInstances []*Server
		g            errgroup.Group
	)
	for _, server := range sb.Servers {
		if server.Status == string(types.InstanceStateNameRunning) {
			if server.Type == RDS {
				rdsInstances = append(rdsInstances, server)
			} else {
				instanceIDs = append(instanceIDs, *server.ID)
			}
		}
	}

	g.Go(func() error {
		return h.PowerOffEC2Instances(instanceIDs)
	})

	g.Go(func() error {
		return h.PowerOffRDSInstances(rdsInstances)
	})

	return g.Wait()
}

// PowerOffEC2Instances powers off the specified EC2 instances.
func (h *AWSProvider) PowerOffEC2Instances(instanceIDs []string) error {
	if h.svc == nil || len(instanceIDs) == 0 {
		return nil
	}
	// We set DryRun to true to check to see if the instance exists, and we have the
	// necessary permissions to monitor the instance.
	input := &ec2.StopInstancesInput{
		InstanceIds: instanceIDs,
		DryRun:      aws.Bool(true),
	}
	_, err := h.svc.StopInstances(context.TODO(), input)
	// If the error code is `DryRunOperation` it means we have the necessary
	// permissions to Stop this instance
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) {
			if ae.ErrorCode() == "DryRunOperation" {
				// Let's now set dry run to be false. This will allow us to start the instances
				input.DryRun = aws.Bool(false)
				_, err = h.svc.StopInstances(context.TODO(), input)
			}
		}
	}
	return err
}

// PowerOffRDSInstances powers off the specified RDS instances.
func (h *AWSProvider) PowerOffRDSInstances(servers []*Server) error {
	if h.rds == nil || len(servers) == 0 {
		return nil
	}
	var g errgroup.Group
	for _, server := range servers {
		s := server
		g.Go(func() error {
			_, err := h.rds.StopDBInstance(context.TODO(), &rds.StopDBInstanceInput{
				DBInstanceIdentifier: s.ID,
			})
			if err != nil {
				return fmt.Errorf("failed to stop RDS instance %s: %v", aws.ToString(server.ID), err)
			}
			return nil
		})
	}
	return g.Wait()
}

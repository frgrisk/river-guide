/*
Copyright © 2023 FRG

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/urfave/negroni/v3"
)

var (
	cfgFile        string
	subscriptionID string
)

const (
	defaultPort = 3000

	defaultReadHeaderTimeout = 3 * time.Second
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "river-guide",
	Short: "River Guide is a simple web interface for managing AWS EC2 instances.",
	Run: func(_ *cobra.Command, _ []string) {
		serve()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.river-guide.yaml)")

	rootCmd.Flags().IntP("port", "p", defaultPort, "port to listen on")
	rootCmd.Flags().String("path-prefix", "/", "prefix to serve the web interface on")
	rootCmd.Flags().StringToStringP("tags", "t", map[string]string{}, "filter instance using tag key-value pairs (e.g. Environment=dev,Name=dev.example.com)")
	rootCmd.Flags().String("title", "Environment Control", "title to display on the web page")
	rootCmd.Flags().String("primary-color", "#333", "primary color for text")
	rootCmd.Flags().String("favicon", "", "path to favicon")
	rootCmd.Flags().Duration("read-header-timeout", defaultReadHeaderTimeout, "timeout for reading the request headers")
	rootCmd.Flags().String("provider", "aws", "cloud provider (aws or azure)")
	rootCmd.Flags().String("resource-group-name", "", "default resource group name (valid only for Azure)")
	rootCmd.Flags().String("subscription-id", "", "subscription ID (valid only for Azure)")

	err := viper.BindPFlags(rootCmd.Flags())
	if err != nil {
		log.Fatal(err)
	}
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".river-guide" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".river-guide")
	}

	viper.SetEnvPrefix("RIVER_GUIDE")
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

type AzureProfile struct {
	Subscriptions []struct {
		ID        string `json:"id"`
		IsDefault bool   `json:"isDefault"`
	} `json:"subscriptions"`
}

// CloudProvider defines common operations for cloud providers
type CloudProvider interface {
	GetServerBank(tags map[string]string) (*ServerBank, error)
	PowerOnAll(*ServerBank) error
	PowerOffAll(*ServerBank) error
	GetStatus() string
}

type AWSProvider struct {
	svc *ec2.Client
}

// GetStatus implements CloudProvider.
func (h *AWSProvider) GetStatus() string {
	panic("unimplemented")
}

// AzureProvider implements CloudProvider for Azure VM
type AzureProvider struct {
	vmClient *armcompute.VirtualMachinesClient
}

// GetStatus implements CloudProvider.
func (a *AzureProvider) GetStatus() string {
	panic("unimplemented")
}

// Server represents an AWS EC2 or Azure VM server.
type Server struct {
	Name              string
	ID                *string
	Status            string
	ResourceGroupName string
}

// ServerBank represents a bank of AWS servers.
type ServerBank struct {
	Servers []*Server
}

// APIHandler handles the API endpoints.
type APIHandler struct {
	provider CloudProvider
	mu       sync.Mutex
}

// GetServerBank based on providers
func (h *APIHandler) GetServerBank(tags map[string]string) (*ServerBank, error) {
	return h.provider.GetServerBank(tags)
}

// PowerOnAll based on providers
func (h *APIHandler) PowerOnAll(sb *ServerBank) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.provider.PowerOnAll(sb)
}

func (h *APIHandler) PowerOffAll(sb *ServerBank) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.provider.PowerOffAll(sb)
}

// GetServerBank queries AWS EC2 instances based on the specified tags.
func (h *AWSProvider) GetServerBank(tags map[string]string) (*ServerBank, error) {
	// if provider is aws then do this if not do that if h.handler is azure then do azure
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

	// Create server bank and populate server list
	serverBank := &ServerBank{}
	for _, reservation := range resp.Reservations {
		for _, instance := range reservation.Instances {
			server := &Server{
				ID:     instance.InstanceId,
				Status: string(instance.State.Name),
			}
			for _, tag := range instance.Tags {
				if *tag.Key == "Name" {
					server.Name = *tag.Value
					break
				}
			}
			serverBank.Servers = append(serverBank.Servers, server)
		}
	}

	// Sort servers by name
	sort.Slice(serverBank.Servers, func(i, j int) bool {
		return serverBank.Servers[i].Name < serverBank.Servers[j].Name
	})

	return serverBank, nil
}

// GetServerBank queries Azure VM instances based on the specified tags.
func (a *AzureProvider) GetServerBank(tags map[string]string) (*ServerBank, error) {
	ctx := context.TODO()
	specifiedResourceGroupName := viper.GetString("resource-group-name")

	pager := a.vmClient.NewListAllPager(nil)
	serverBank := &ServerBank{}

	for pager.More() {
		result, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get VM instances: %v", err)
		}

		for _, vm := range result.Value {
			// Extract the resource group name from each vm ID
			resourceGroupName := extractResourceGroupName(*vm.ID)
			// If a specific resource group is specified, skip unmatched VMs
			if specifiedResourceGroupName != "" && resourceGroupName != specifiedResourceGroupName {
				continue
			}
			match := true
			for key, value := range tags {
				if vmValue, ok := vm.Tags[key]; !ok || *vmValue != value {
					match = false
					break
				}
			}

			if match {
				// Get the instance view for the VM to access its status
				instanceView, err := a.vmClient.InstanceView(ctx, resourceGroupName, *vm.Name, nil)
				if err != nil {
					return nil, fmt.Errorf("failed to get instance view: %v", err)
				}

				var powerState string
				for _, s := range instanceView.Statuses {
					if s.Code != nil && strings.HasPrefix(*s.Code, "PowerState/") {
						powerState = *s.Code
						break
					}
				}
				status := normalizeStatus(powerState)

				server := &Server{
					ID:                vm.ID,
					Name:              *vm.Name,
					Status:            status,
					ResourceGroupName: resourceGroupName,
				}
				serverBank.Servers = append(serverBank.Servers, server)
			}
		}
	}

	// Sort servers by name
	sort.Slice(serverBank.Servers, func(i, j int) bool {
		return serverBank.Servers[i].Name < serverBank.Servers[j].Name
	})

	return serverBank, nil
}

func extractResourceGroupName(vmID string) string {
	parts := strings.Split(vmID, "/")
	for i, part := range parts {
		if part == "resourceGroups" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// GetStatus returns the overall status of the server bank.
func (sb *ServerBank) GetStatus() string {
	runningCount := 0
	for _, server := range sb.Servers {
		if server.Status == string(types.InstanceStateNameRunning) {
			runningCount++
		} else if server.Status == string(types.InstanceStateNameStopping) || server.Status == string(types.InstanceStateNamePending) {
			return string(types.InstanceStateNamePending)
		}
	}

	if runningCount == len(sb.Servers) {
		return string(types.InstanceStateNameRunning)
	}

	return string(types.InstanceStateNameStopped)
}

func normalizeStatus(azureStatus string) string {
	switch azureStatus {
	case "PowerState/running":
		return string(types.InstanceStateNameRunning)
	case "PowerState/stopped", "PowerState/deallocated":
		return string(types.InstanceStateNameStopped)
	default:
		return string(types.InstanceStateNamePending)
	}
}

// PowerOnAll powers on all the servers in the bank and updates their statuses.
func (h *AWSProvider) PowerOnAll(sb *ServerBank) error {
	var instanceIDs []string
	for _, server := range sb.Servers {
		if server.Status == string(types.InstanceStateNameStopped) {
			instanceIDs = append(instanceIDs, *server.ID)
		}
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

// PowerOffAll powers off all the servers in the bank and updates their statuses.
func (h *AWSProvider) PowerOffAll(sb *ServerBank) error {
	var instanceIDs []string
	for _, server := range sb.Servers {
		if server.Status == string(types.InstanceStateNameRunning) {
			instanceIDs = append(instanceIDs, *server.ID)
		}
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

// PowerOnAll powers on all the servers in the bank and updates their statuses.
func (a *AzureProvider) PowerOnAll(sb *ServerBank) error {
	ctx := context.TODO()

	for _, server := range sb.Servers {
		if server.Status == string(types.InstanceStateNameStopped) {
			_, err := a.vmClient.BeginStart(ctx, server.ResourceGroupName, server.Name, nil)
			if err != nil {
				return fmt.Errorf("failed to start VM %s: %v", server.Name, err)
			}
		}
	}

	return nil
}

// PowerOffAll powers off all the servers in the bank and updates their statuses.
func (a *AzureProvider) PowerOffAll(sb *ServerBank) error {
	ctx := context.TODO()

	for _, server := range sb.Servers {
		if server.Status == string(types.InstanceStateNameRunning) {
			_, err := a.vmClient.BeginDeallocate(ctx, server.ResourceGroupName, server.Name, nil)
			if err != nil {
				return fmt.Errorf("failed to stop VM %s: %v", server.Name, err)
			}
		}
	}

	return nil
}

//go:embed assets/index.gohtml
var indexTemplate string

// IndexHandler handles the index page.
func (h *APIHandler) IndexHandler(w http.ResponseWriter, _ *http.Request) {
	tmpl := template.Must(template.New("index").Parse(indexTemplate))
	sb, err := h.GetServerBank(viper.GetStringMapString("tags"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type TemplateData struct {
		Title                  string
		ActionText             string
		PrimaryColor           string
		TogglePath             string
		Provider               string
		SpecifiedResourceGroup string
		Servers                []*Server
	}

	data := TemplateData{
		Title:                  viper.GetString("title"),
		Servers:                sb.Servers,
		ActionText:             "Pending",
		PrimaryColor:           viper.GetString("primary-color"),
		Provider:               viper.GetString("provider"),
		SpecifiedResourceGroup: viper.GetString("resource-group-name"),
		TogglePath:             filepath.Join(viper.GetString("path-prefix"), "toggle"),
	}
	status := sb.GetStatus()
	if status == string(types.InstanceStateNameRunning) {
		data.ActionText = "Stop"
	} else if status == string(types.InstanceStateNameStopped) {
		data.ActionText = "Start"
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// ToggleHandler handles the start/stop button toggle.
func (h *APIHandler) ToggleHandler(w http.ResponseWriter, _ *http.Request) {
	sb, err := h.GetServerBank(viper.GetStringMapString("tags"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	status := sb.GetStatus()
	if status == string(types.InstanceStateNameRunning) {
		err = h.PowerOffAll(sb)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		err = h.PowerOnAll(sb)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Return success response
	w.WriteHeader(http.StatusOK)
}

//go:embed assets/FRG-icon-for-Google-tab.jpg
var favicon []byte

func FaviconHandler(w http.ResponseWriter, r *http.Request) {
	if viper.GetString("favicon") == "" {
		_, err := w.Write(favicon)
		if err != nil {
			panic(err)
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	http.ServeFile(w, r, viper.GetString("favicon"))
}

func getVMClient(subscriptionID string) (*armcompute.VirtualMachinesClient, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}

	client, err := armcompute.NewVirtualMachinesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func serve() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	provider := viper.GetString("provider")

	var cloudProvider CloudProvider
	switch strings.ToLower(provider) {
	case "aws":
		// Create an AWS session
		cfg, err := config.LoadDefaultConfig(
			context.TODO(),
		)
		if err != nil {
			log.Fatal(err)
		}
		cloudProvider = &AWSProvider{svc: ec2.NewFromConfig(cfg)}
	case "azure":
		subscriptionID = viper.GetString("subscription-id")
		if subscriptionID == "" {
			log.Fatal("Azure subscription ID is required when using Azure provider.")
		}
		client, err := getVMClient(subscriptionID)
		if err != nil {
			log.Fatalf("Failed to create VM client: %v", err)
		}
		// Create provider
		cloudProvider = &AzureProvider{
			vmClient: client,
		}

	default:
		log.Fatalf("Error initialising provider client: %s", provider)
	}

	apiHandler := &APIHandler{provider: cloudProvider}
	// Create a new router
	r := mux.NewRouter()
	rp := r.PathPrefix(viper.GetString("path-prefix")).Subrouter()

	// Define API routes
	rp.HandleFunc("/", apiHandler.IndexHandler).Methods("GET")
	rp.HandleFunc("/favicon.ico", FaviconHandler).Methods("GET")
	rp.HandleFunc("/toggle", apiHandler.ToggleHandler).Methods("POST")

	// Add middleware
	n := negroni.Classic() // Includes some default middlewares
	n.UseHandler(rp)

	server := &http.Server{
		Addr:              ":" + strconv.Itoa(viper.GetInt("port")),
		Handler:           n,
		ReadHeaderTimeout: viper.GetDuration("read-header-timeout"),
	}

	// Start the HTTP server
	log.Infof("Server running on http://localhost:%v%v", viper.GetInt("port"), viper.GetString("path-prefix"))
	log.Fatal(server.ListenAndServe())
}

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

var cfgFile string

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

	rootCmd.Flags().IntP("port", "p", 3000, "port to listen on")
	rootCmd.Flags().String("path-prefix", "/", "prefix to serve the web interface on")
	rootCmd.Flags().StringToStringP("tags", "t", map[string]string{}, "filter instance using tag key-value pairs (e.g. Environment=dev,Name=dev.example.com)")
	rootCmd.Flags().String("title", "Environment Control", "title to display on the web page")
	rootCmd.Flags().String("primary-color", "#333", "primary color for text")
	rootCmd.Flags().String("favicon", "", "path to favicon")

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

// Server represents an AWS server.
type Server struct {
	Name   string
	ID     *string
	Status types.InstanceStateName
}

// ServerBank represents a bank of AWS servers.
type ServerBank struct {
	Servers []*Server
}

// APIHandler handles the API endpoints.
type APIHandler struct {
	mu  sync.Mutex
	svc *ec2.Client
}

// GetServerBank queries AWS EC2 instances based on the specified tags.
func (h *APIHandler) GetServerBank(tags map[string]string) (*ServerBank, error) {
	// Build the filter for tag-based instance query
	var filters []types.Filter
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
				Status: instance.State.Name,
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

// GetStatus returns the overall status of the server bank.
func (sb *ServerBank) GetStatus() types.InstanceStateName {
	runningCount := 0
	for _, server := range sb.Servers {
		if server.Status == types.InstanceStateNameRunning {
			runningCount++
		} else if server.Status == types.InstanceStateNameStopping || server.Status == types.InstanceStateNamePending {
			return types.InstanceStateNamePending
		}
	}

	if runningCount == len(sb.Servers) {
		return types.InstanceStateNameRunning
	}

	return types.InstanceStateNameStopped
}

// PowerOnAll powers on all the servers in the bank and updates their statuses.
func (h *APIHandler) PowerOnAll(sb *ServerBank) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	var instanceIDs []string
	for _, server := range sb.Servers {
		if server.Status == types.InstanceStateNameStopped {
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
func (h *APIHandler) PowerOffAll(sb *ServerBank) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	var instanceIDs []string
	for _, server := range sb.Servers {
		if server.Status == types.InstanceStateNameRunning {
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
		Title        string
		ActionText   string
		Servers      []*Server
		PrimaryColor string
		TogglePath   string
	}

	data := TemplateData{
		Title:        viper.GetString("title"),
		Servers:      sb.Servers,
		ActionText:   "Pending",
		PrimaryColor: viper.GetString("primary-color"),
		TogglePath:   filepath.Join(viper.GetString("path-prefix"), "toggle"),
	}

	status := sb.GetStatus()
	if status == types.InstanceStateNameRunning {
		data.ActionText = "Stop"
	} else if status == types.InstanceStateNameStopped {
		data.ActionText = "Start"
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

	if status == types.InstanceStateNameRunning {
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

func serve() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	// Create an AWS session
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Create API handler with the server bank
	apiHandler := &APIHandler{svc: ec2.NewFromConfig(cfg)}

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

	// Start the HTTP server
	log.Infof("Server running on http://localhost:%v%v", viper.GetInt("port"), viper.GetString("path-prefix"))
	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(viper.GetInt("port")), n))
}

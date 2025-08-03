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

	"crypto/rand"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/urfave/negroni/v3"
)

var (
	cfgFile        string
	subscriptionID string
	oidcProvider   *oidc.Provider
	oidcVerifier   *oidc.IDTokenVerifier
	oauth2Config   *oauth2.Config
	sessionStore   *sessions.CookieStore
	allowedGroups  []string
	oidcEnabled    bool
)

type ServerType string

const (
	defaultPort = 3000

	defaultReadHeaderTimeout = 3 * time.Second

	EC2 ServerType = "EC2"
	RDS ServerType = "RDS"
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
	rootCmd.Flags().StringToStringP("tags", "t", map[string]string{}, "filter instances using tag key-value pairs (e.g. Environment=dev,Name=dev.example.com)")
	rootCmd.Flags().String("title", "Environment Control", "title to display on the web page")
	rootCmd.Flags().String("primary-color", "#333", "primary color for text")
	rootCmd.Flags().String("favicon", "", "path to favicon")
	rootCmd.Flags().Duration("read-header-timeout", defaultReadHeaderTimeout, "timeout for reading the request headers")
	rootCmd.Flags().String("provider", "aws", "cloud provider (aws or azure)")
	rootCmd.Flags().String("resource-group-name", "", "filter instances based on their resource group membership (only used with the Azure provider)")
	rootCmd.Flags().String("subscription-id", "", "subscription ID (required for Azure)")
	rootCmd.Flags().Bool("rds", false, "enable RDS support")
	rootCmd.Flags().String("oidc-issuer", "", "OIDC issuer URL")
	rootCmd.Flags().String("oidc-client-id", "", "OIDC client ID")
	rootCmd.Flags().String("oidc-client-secret", "", "OIDC client secret")
	rootCmd.Flags().String("oidc-redirect-url", "", "OIDC redirect URL")
	rootCmd.Flags().StringSlice("oidc-groups", []string{}, "allowed OIDC groups")
	rootCmd.Flags().StringSlice("oidc-scopes", []string{}, "OIDC scopes to request (defaults to openid, profile, email, and groups if --oidc-groups is set)")

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
	Type              ServerType
}

// ServerBank represents a bank of servers.
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
			if specifiedResourceGroupName != "" && !strings.EqualFold(resourceGroupName, specifiedResourceGroupName) {
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

//go:embed assets/landing.gohtml
var landingTemplate string

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
		PrimaryColor string
		TogglePath   string
		Servers      []*Server
	}

	data := TemplateData{
		Title:        viper.GetString("title"),
		Servers:      sb.Servers,
		ActionText:   "Pending",
		PrimaryColor: viper.GetString("primary-color"),
		TogglePath:   filepath.Join(viper.GetString("path-prefix"), "toggle"),
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

// LandingHandler serves the landing page prompting for login.
func LandingHandler(w http.ResponseWriter, _ *http.Request) {
	tmpl := template.Must(template.New("landing").Parse(landingTemplate))
	data := struct {
		Title        string
		PrimaryColor string
		LoginPath    string
	}{
		Title:        viper.GetString("title"),
		PrimaryColor: viper.GetString("primary-color"),
		LoginPath:    filepath.Join(viper.GetString("path-prefix"), "login"),
	}
	if err := tmpl.Execute(w, data); err != nil {
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
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(favicon)
		if err != nil {
			panic(err)
		}
		return
	}
	http.ServeFile(w, r, viper.GetString("favicon"))
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if !oidcEnabled {
		http.Redirect(w, r, viper.GetString("path-prefix"), http.StatusFound)
		return
	}
	state := uuid.NewString()
	session, err := sessionStore.Get(r, "oidc")
	if err != nil {
		log.Printf("LoginHandler: session error: %v", err)
		http.Error(w, fmt.Sprintf("session error: %v", err), http.StatusInternalServerError)
		return
	}
	session.Values["state"] = state
	if err := session.Save(r, w); err != nil {
		log.Printf("LoginHandler: failed to save session: %v", err)
		http.Error(w, fmt.Sprintf("failed to save session: %v", err), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
}

func CallbackHandler(w http.ResponseWriter, r *http.Request) {
	if !oidcEnabled {
		http.Redirect(w, r, viper.GetString("path-prefix"), http.StatusFound)
		return
	}
	
	// Check for OAuth error response
	if errCode := r.URL.Query().Get("error"); errCode != "" {
		errDesc := r.URL.Query().Get("error_description")
		if errDesc == "" {
			errDesc = "Authentication failed"
		}
		errorMsg := fmt.Sprintf("OAuth error: %s - %s", errCode, errDesc)
		http.Error(w, errorMsg, http.StatusBadRequest)
		return
	}
	
	session, err := sessionStore.Get(r, "oidc")
	if err != nil {
		log.Printf("CallbackHandler: session error: %v", err)
		http.Error(w, fmt.Sprintf("session error: %v", err), http.StatusInternalServerError)
		return
	}
	storedState, ok := session.Values["state"].(string)
	if !ok || r.URL.Query().Get("state") != storedState {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	token, err := oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		errorMsg := fmt.Sprintf("Token exchange failed: %v", err)
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No ID token in response. Check OIDC provider configuration.", http.StatusInternalServerError)
		return
	}
	idToken, err := oidcVerifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		errorMsg := fmt.Sprintf("Invalid ID token: %v", err)
		http.Error(w, errorMsg, http.StatusUnauthorized)
		return
	}
	var claims struct {
		Groups []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "failed to parse claims", http.StatusInternalServerError)
		return
	}
	if len(allowedGroups) > 0 && !hasAllowedGroup(claims.Groups) {
		errorMsg := fmt.Sprintf("Access denied. User groups %v are not in allowed groups %v", claims.Groups, allowedGroups)
		http.Error(w, errorMsg, http.StatusForbidden)
		return
	}
	session.Values["id_token"] = rawIDToken
	session.Values["token_expiry"] = idToken.Expiry.Unix()
	delete(session.Values, "state")
	if err := session.Save(r, w); err != nil {
		log.Printf("CallbackHandler: failed to save session: %v", err)
		http.Error(w, fmt.Sprintf("failed to save session: %v", err), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, viper.GetString("path-prefix"), http.StatusFound)
}

func hasAllowedGroup(groups []string) bool {
	for _, g := range groups {
		for _, a := range allowedGroups {
			if g == a {
				return true
			}
		}
	}
	return false
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !oidcEnabled {
			next.ServeHTTP(w, r)
			return
		}
		pathPrefix := viper.GetString("path-prefix")
		path := strings.TrimPrefix(r.URL.Path, pathPrefix)
		path = strings.TrimPrefix(path, "/")
		if path == "login" || path == "callback" || path == "favicon.ico" || strings.HasPrefix(path, "login") || strings.HasPrefix(path, "callback") {
			next.ServeHTTP(w, r)
			return
		}
		session, err := sessionStore.Get(r, "oidc")
		if err != nil {
			http.Redirect(w, r, viper.GetString("path-prefix")+"login", http.StatusFound)
			return
		}
		rawIDToken, ok := session.Values["id_token"].(string)
		if !ok {
			if r.Method == http.MethodGet && (path == "" || path == "/") {
				LandingHandler(w, r)
			} else {
				loginPath := strings.TrimSuffix(pathPrefix, "/") + "/login"
				http.Redirect(w, r, loginPath, http.StatusFound)
			}
			return
		}
		expiry, _ := session.Values["token_expiry"].(int64)
		if expiry > 0 && time.Now().Unix() > expiry {
			http.Redirect(w, r, viper.GetString("path-prefix")+"login", http.StatusFound)
			return
		}
		idToken, err := oidcVerifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			loginPath := strings.TrimSuffix(viper.GetString("path-prefix"), "/") + "/login"
			http.Redirect(w, r, loginPath, http.StatusFound)
			return
		}
		var claims struct {
			Groups []string `json:"groups"`
		}
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, "failed to parse claims", http.StatusInternalServerError)
			return
		}
		if len(allowedGroups) > 0 && !hasAllowedGroup(claims.Groups) {
			http.Error(w, "Access denied: user is not in an allowed group", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
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
	enableRds := viper.GetBool("rds")

	oidcIssuer := viper.GetString("oidc-issuer")
	oidcClientID := viper.GetString("oidc-client-id")
	oidcClientSecret := viper.GetString("oidc-client-secret")
	oidcRedirectURL := viper.GetString("oidc-redirect-url")
	allowedGroups = viper.GetStringSlice("oidc-groups")
	oidcScopes := viper.GetStringSlice("oidc-scopes")

	if oidcIssuer != "" || oidcClientID != "" || oidcClientSecret != "" || oidcRedirectURL != "" {
		if oidcIssuer == "" || oidcClientID == "" || oidcClientSecret == "" || oidcRedirectURL == "" {
			log.Fatal("OIDC configuration incomplete: all of issuer, client-id, client-secret, and redirect-url must be provided")
		}
		var err error
		oidcEnabled = true
		ctx := context.TODO()
		oidcProvider, err = oidc.NewProvider(ctx, oidcIssuer)
		if err != nil {
			log.Fatalf("failed to init oidc provider: %v", err)
		}
		oidcVerifier = oidcProvider.Verifier(&oidc.Config{ClientID: oidcClientID})
		
		// Use custom scopes if provided, otherwise use defaults
		var scopes []string
		if len(oidcScopes) > 0 {
			scopes = oidcScopes
		} else {
			scopes = []string{oidc.ScopeOpenID, "profile", "email"}
			// Only request groups scope if allowed groups are configured
			if len(allowedGroups) > 0 {
				scopes = append(scopes, "groups")
			}
		}
		
		oauth2Config = &oauth2.Config{
			ClientID:     oidcClientID,
			ClientSecret: oidcClientSecret,
			Endpoint:     oidcProvider.Endpoint(),
			RedirectURL:  oidcRedirectURL,
			Scopes:       scopes,
		}
		sessionKey := make([]byte, 32)
		if _, err := rand.Read(sessionKey); err != nil {
			log.Fatalf("failed to generate session key: %v", err)
		}
		sessionStore = sessions.NewCookieStore(sessionKey)
		pathPrefix := viper.GetString("path-prefix")
		if pathPrefix == "" {
			pathPrefix = "/"
		} else if !strings.HasSuffix(pathPrefix, "/") {
			pathPrefix = pathPrefix + "/"
		}
		sessionStore.Options = &sessions.Options{
			Path:     pathPrefix,
			MaxAge:   86400, // 24 hours
			HttpOnly: true,
			Secure:   strings.HasPrefix(oidcRedirectURL, "https://"),
			SameSite: http.SameSiteLaxMode,
		}
		log.Printf("OIDC session configuration: Path=%s, Secure=%v, MaxAge=%d", pathPrefix, strings.HasPrefix(oidcRedirectURL, "https://"), 86400)
	}

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
		if cfg.Region == "" {
			log.Fatal("AWS region is required when using AWS provider. Set the AWS_REGION environment variable.")
		}
		var rdsClient *rds.Client
		if enableRds {
			rdsClient = rds.NewFromConfig(cfg)
		}
		cloudProvider = &AWSProvider{
			svc: ec2.NewFromConfig(cfg),
			rds: rdsClient,
		}
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
	rp.HandleFunc("/login", LoginHandler).Methods("GET")
	rp.HandleFunc("/callback", CallbackHandler).Methods("GET")

	// Add middleware
	n := negroni.Classic() // Includes some default middlewares
	n.UseHandler(AuthMiddleware(rp))

	server := &http.Server{
		Addr:              ":" + strconv.Itoa(viper.GetInt("port")),
		Handler:           n,
		ReadHeaderTimeout: viper.GetDuration("read-header-timeout"),
	}

	// Start the HTTP server
	log.Infof("Server running on http://localhost:%v%v", viper.GetInt("port"), viper.GetString("path-prefix"))
	log.Fatal(server.ListenAndServe())
}

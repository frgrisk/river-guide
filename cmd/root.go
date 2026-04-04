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
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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

const (
	sessionKeySize       = 32
	sessionMaxLength     = 65536 // 64KB limit for filesystem sessions
	maxTotalClaimSize    = 2000  // Reserve space for other session data in CookieStore
	hexEncodingMultiple  = 2     // Hex encoding doubles the character count
	defaultSessionMaxAge = 86400 // 24 hours
)

type contextKey string

const userSubjectKey contextKey = "user_subject"

var (
	cfgFile        string
	subscriptionID string
	oidcProvider   *oidc.Provider
	oidcVerifier   *oidc.IDTokenVerifier
	oauth2Config   *oauth2.Config
	sessionStore   sessions.Store
	allowedGroups  []string
	oidcEnabled    bool
)

// Custom logger that includes user information
type UserAwareLogger struct {
	*log.Logger
}

func (l *UserAwareLogger) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	start := time.Now()

	// Get source IP address
	sourceIP := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one (original client)
		if idx := strings.Index(forwarded, ","); idx != -1 {
			sourceIP = strings.TrimSpace(forwarded[:idx])
		} else {
			sourceIP = strings.TrimSpace(forwarded)
		}
	} else if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		sourceIP = strings.TrimSpace(realIP)
	}

	userInfo := ""
	if claims := r.Context().Value(userSubjectKey); claims != nil {
		if claimsMap, ok := claims.(map[string]string); ok && len(claimsMap) > 0 {
			parts := make([]string, 0, len(claimsMap))
			for key, value := range claimsMap {
				parts = append(parts, fmt.Sprintf("%s=%s", key, value))
			}
			userInfo = fmt.Sprintf(" user=%s", strings.Join(parts, ","))
		}
	}
	next(rw, r)
	res := rw.(negroni.ResponseWriter)
	l.Printf("%s %s%s from=%s -> %d %s in %v",
		r.Method,
		r.URL.RequestURI(),
		userInfo,
		sourceIP,
		res.Status(),
		http.StatusText(res.Status()),
		time.Since(start),
	)
}

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
	rootCmd.Flags().String("accent-color", "#93C30B", "accent color for buttons and highlights")
	rootCmd.Flags().String("background-color", "#244A66", "background color")
	rootCmd.Flags().String("logo", "", "URL for logo image on login page (used as img src, not read from disk)")
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
	rootCmd.Flags().StringSlice("oidc-log-claims", []string{"sub"}, "OIDC claims to include in request logs (e.g. sub, email, name)")
	rootCmd.Flags().String("session-secret", "", "session secret key (hex-encoded, 64 characters). If not provided, a random key is generated.")
	rootCmd.Flags().Int("session-max-age", defaultSessionMaxAge, "session cookie lifetime in seconds (default: 86400 = 24 hours)")
	rootCmd.Flags().String("tls-cert", "", "path to TLS certificate file (enables HTTPS)")
	rootCmd.Flags().String("tls-key", "", "path to TLS private key file (requires --tls-cert)")
	rootCmd.MarkFlagsRequiredTogether("tls-cert", "tls-key")

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

//go:embed assets/error.gohtml
var errorTemplate string

// ErrorPageData represents data for the error page template
type ErrorPageData struct {
	Title            string
	Subtitle         string
	Message          string
	Type             string
	HomePath         string
	LogoutPath       string
	TechnicalDetails string
	AccentColor      string
	BackgroundColor  string
	ShowRetry        bool
	ShowHome         bool
	ShowLogout       bool
	ShowContact      bool
}

// RenderErrorPage renders a user-friendly error page
func RenderErrorPage(w http.ResponseWriter, r *http.Request, statusCode int, title, subtitle, message string, errorType string) {
	tmpl := template.Must(template.New("error").Parse(errorTemplate))

	data := ErrorPageData{
		Title:           title,
		Subtitle:        subtitle,
		Message:         message,
		Type:            errorType,
		ShowRetry:       true,
		ShowHome:        true,
		ShowLogout:      oidcEnabled,
		ShowContact:     true,
		HomePath:        viper.GetString("path-prefix"),
		LogoutPath:      path.Join(viper.GetString("path-prefix"), "logout"),
		AccentColor:     viper.GetString("accent-color"),
		BackgroundColor: viper.GetString("background-color"),
	}

	// Add technical details for debugging
	if message != "" {
		data.TechnicalDetails = fmt.Sprintf("Status: %d\nPath: %s\nMethod: %s\nTime: %s\nError: %s",
			statusCode, r.URL.Path, r.Method, time.Now().Format(time.RFC3339), message)
	}

	w.WriteHeader(statusCode)
	if err := tmpl.Execute(w, data); err != nil {
		// Fallback to simple error if template fails
		http.Error(w, fmt.Sprintf("%s: %s", title, subtitle), statusCode)
	}
}

// IndexHandler handles the index page.
func (h *APIHandler) IndexHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("index").Parse(indexTemplate))
	sb, err := h.GetServerBank(viper.GetStringMapString("tags"))
	if err != nil {
		log.Printf("IndexHandler: failed to get server bank: %v", err)
		RenderErrorPage(w, r, http.StatusInternalServerError,
			"Server Connection Failed",
			"Unable to retrieve server information from the cloud provider",
			"Please try again or contact your administrator if the problem persists.",
			"error")
		return
	}

	type TemplateData struct {
		Title           string
		ActionText      string
		AccentColor     string
		BackgroundColor string
		TogglePath      string
		LogoutPath      string
		UserEmail       string
		UserName        string
		UserSubject     string
		Servers         []*Server
		OIDCEnabled     bool
	}

	data := TemplateData{
		Title:           viper.GetString("title"),
		Servers:         sb.Servers,
		ActionText:      "Pending",
		AccentColor:     viper.GetString("accent-color"),
		BackgroundColor: viper.GetString("background-color"),
		TogglePath:      path.Join(viper.GetString("path-prefix"), "toggle"),
		LogoutPath:      path.Join(viper.GetString("path-prefix"), "logout"),
		OIDCEnabled:     oidcEnabled,
	}

	// Extract user information from context if available
	if claims := r.Context().Value(userSubjectKey); claims != nil {
		if claimsMap, ok := claims.(map[string]string); ok {
			data.UserEmail = claimsMap["email"]
			data.UserName = claimsMap["name"]
			data.UserSubject = claimsMap["sub"]
		}
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
		Title           string
		AccentColor     string
		BackgroundColor string
		Logo            string
		LoginPath       string
	}{
		Title:           viper.GetString("title"),
		AccentColor:     viper.GetString("accent-color"),
		BackgroundColor: viper.GetString("background-color"),
		Logo:            viper.GetString("logo"),
		LoginPath:       path.Join(viper.GetString("path-prefix"), "login"),
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
		clearSessionAndRedirectToLogin(w, r, fmt.Sprintf("LoginHandler: session error: %v", err))
		return
	}
	session.Values["state"] = state
	if err := session.Save(r, w); err != nil {
		clearSessionAndRedirectToLogin(w, r, fmt.Sprintf("LoginHandler: failed to save session: %v", err))
		return
	}
	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if !oidcEnabled {
		http.Redirect(w, r, viper.GetString("path-prefix"), http.StatusFound)
		return
	}

	// Clear the session
	session, err := sessionStore.Get(r, "oidc")
	if err != nil {
		log.Printf("LogoutHandler: failed to get session: %v", err)
		// Continue with logout even if session retrieval fails
	} else {
		// Clear all session values
		for key := range session.Values {
			delete(session.Values, key)
		}
		session.Options.MaxAge = -1 // Mark session for deletion
		if err := session.Save(r, w); err != nil {
			log.Printf("LogoutHandler: failed to save session: %v", err)
		}
	}

	// Clear the session cookie manually as well
	pathPrefix := viper.GetString("path-prefix")
	if pathPrefix == "" {
		pathPrefix = "/"
	} else if !strings.HasSuffix(pathPrefix, "/") {
		pathPrefix += "/"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "oidc",
		Value:    "",
		Path:     pathPrefix,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   strings.HasPrefix(viper.GetString("oidc-redirect-url"), "https://"),
		SameSite: http.SameSiteLaxMode,
	})

	log.Printf("User logged out")
	http.Redirect(w, r, viper.GetString("path-prefix"), http.StatusFound)
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

		// Map common OAuth errors to user-friendly messages
		var title, subtitle string
		switch errCode {
		case "access_denied":
			title = "Authentication Cancelled"
			subtitle = "You cancelled the login process or denied access"
		case "invalid_request":
			title = "Authentication Error"
			subtitle = "There was a problem with the login request"
		case "unauthorized_client":
			title = "Configuration Error"
			subtitle = "The application is not properly configured for authentication"
		case "server_error", "temporarily_unavailable":
			title = "Service Temporarily Unavailable"
			subtitle = "The authentication service is experiencing issues"
		default:
			title = "Authentication Failed"
			subtitle = "Unable to complete the login process"
		}

		RenderErrorPage(w, r, http.StatusBadRequest, title, subtitle, errDesc, "warning")
		log.Printf("OAuth error: %s", errorMsg)
		return
	}

	session, err := sessionStore.Get(r, "oidc")
	if err != nil {
		clearSessionAndRedirectToLogin(w, r, fmt.Sprintf("CallbackHandler: session error: %v", err))
		return
	}
	storedState, ok := session.Values["state"].(string)
	if !ok || r.URL.Query().Get("state") != storedState {
		clearSessionAndRedirectToLogin(w, r, "CallbackHandler: state mismatch in OAuth callback")
		return
	}
	token, err := oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("CallbackHandler: token exchange failed: %v", err)
		clearSessionAndRedirectToLogin(w, r, "CallbackHandler: token exchange failed")
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		clearSessionAndRedirectToLogin(w, r, "CallbackHandler: no id_token in token response")
		return
	}
	idToken, err := oidcVerifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		log.Printf("CallbackHandler: invalid ID token: %v", err)
		clearSessionAndRedirectToLogin(w, r, "CallbackHandler: authentication failed")
		return
	}
	// Parse all claims into a map for flexible access
	var allClaims map[string]interface{}
	if err := idToken.Claims(&allClaims); err != nil {
		log.Printf("CallbackHandler: failed to parse claims: %v", err)
		clearSessionAndRedirectToLogin(w, r, "CallbackHandler: failed to parse claims")
		return
	}

	// Extract groups for authorization
	var groups []string
	if groupsVal, ok := allClaims["groups"]; ok {
		if groupsSlice, ok := groupsVal.([]interface{}); ok {
			for _, g := range groupsSlice {
				if groupStr, ok := g.(string); ok {
					groups = append(groups, groupStr)
				}
			}
		}
	}

	if len(allowedGroups) > 0 && !hasAllowedGroup(groups) {
		log.Printf("Access denied: user groups %v are not in allowed groups %v", groups, allowedGroups)
		// Clear session to prevent stale auth data from a prior login persisting
		for key := range session.Values {
			delete(session.Values, key)
		}
		session.Options.MaxAge = -1
		if saveErr := session.Save(r, w); saveErr != nil {
			log.Printf("CallbackHandler: failed to clear session after access denied: %v", saveErr)
		}
		RenderErrorPage(w, r, http.StatusForbidden,
			"Access Denied",
			"Your account doesn't have permission to access this application",
			"Please contact your administrator to request access or use a different account.",
			"warning")
		return
	}

	// Store authorization result instead of all groups to save session space
	isAuthorized := len(allowedGroups) == 0 || hasAllowedGroup(groups)
	log.Printf("User has %d groups, authorized: %v", len(groups), isAuthorized)
	session.Values["is_authorized"] = isAuthorized

	// Optional: Store only the first matching group for logging (much smaller)
	if len(allowedGroups) > 0 && isAuthorized {
		for _, userGroup := range groups {
			for _, allowedGroup := range allowedGroups {
				if userGroup == allowedGroup {
					session.Values["authorized_group"] = allowedGroup
					break
				}
			}
			if _, exists := session.Values["authorized_group"]; exists {
				break
			}
		}
	}

	// Store configurable claims for logging as individual session keys (avoids gob map serialization issues)
	logClaims := viper.GetStringSlice("oidc-log-claims")
	// Clear any existing claim keys first
	for key := range session.Values {
		if keyStr, ok := key.(string); ok && strings.HasPrefix(keyStr, "user_claim_") {
			delete(session.Values, key)
		}
	}
	// Store each claim as a separate session key with size management for CookieStore
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		// Lambda environment - use size management for CookieStore
		totalClaimSize := 0
		for _, claimName := range logClaims {
			claimValue, exists := allClaims[claimName]
			if !exists {
				continue
			}
			claimStr := fmt.Sprintf("%v", claimValue)
			claimSize := len("user_claim_"+claimName) + len(claimStr)

			if totalClaimSize+claimSize > maxTotalClaimSize {
				log.Printf("Warning: Skipping claim '%s' (%d bytes) to keep session under size limit", claimName, claimSize)
				continue
			}

			session.Values["user_claim_"+claimName] = claimStr
			totalClaimSize += claimSize
		}
		log.Printf("Stored %d bytes of claims in session", totalClaimSize)
	} else {
		// Regular deployment - FilesystemStore can handle larger sessions
		for _, claimName := range logClaims {
			if claimValue, exists := allClaims[claimName]; exists {
				session.Values["user_claim_"+claimName] = fmt.Sprintf("%v", claimValue)
			}
		}
	}
	session.Values["token_expiry"] = idToken.Expiry.Unix()
	session.Values["authenticated"] = true
	delete(session.Values, "state")

	if err := session.Save(r, w); err != nil {
		log.Printf("CallbackHandler: failed to save session: %v", err)
		http.Error(w, "failed to save session", http.StatusInternalServerError)
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

// clearSessionAndRedirectToLogin clears the session cookie and redirects to login
func clearSessionAndRedirectToLogin(w http.ResponseWriter, r *http.Request, logMsg string) {
	log.Print(logMsg)

	// Try to properly clear the session through the store first
	if session, err := sessionStore.Get(r, "oidc"); err == nil {
		// Clear all session values
		for key := range session.Values {
			delete(session.Values, key)
		}
		session.Options.MaxAge = -1
		// Attempt to save the cleared session (ignore errors since session might be corrupted)
		_ = session.Save(r, w)
	}

	// Also clear the session cookie manually as a fallback
	pathPrefix := viper.GetString("path-prefix")
	if pathPrefix == "" {
		pathPrefix = "/"
	} else if !strings.HasSuffix(pathPrefix, "/") {
		pathPrefix += "/"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "oidc",
		Value:    "",
		Path:     pathPrefix,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil || strings.Contains(strings.ToLower(r.Header.Get("X-Forwarded-Proto")), "https"),
		SameSite: http.SameSiteLaxMode,
	})

	loginPath := strings.TrimSuffix(viper.GetString("path-prefix"), "/") + "/login"
	http.Redirect(w, r, loginPath, http.StatusFound)
}

// AuthMiddleware implements negroni.Handler for OIDC authentication
type AuthMiddleware struct{}

func (a *AuthMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if !oidcEnabled {
		next(w, r)
		return
	}
	pathPrefix := viper.GetString("path-prefix")
	reqPath := strings.TrimPrefix(r.URL.Path, pathPrefix)
	reqPath = strings.TrimPrefix(reqPath, "/")
	if reqPath == "login" || reqPath == "logout" || reqPath == "callback" || reqPath == "favicon.ico" || strings.HasPrefix(reqPath, "login") || strings.HasPrefix(reqPath, "logout") || strings.HasPrefix(reqPath, "callback") {
		next(w, r)
		return
	}
	session, err := sessionStore.Get(r, "oidc")
	if err != nil {
		clearSessionAndRedirectToLogin(w, r, fmt.Sprintf("AuthMiddleware: session error: %v", err))
		return
	}
	authenticated, ok := session.Values["authenticated"].(bool)
	if !ok || !authenticated {
		if r.Method == http.MethodGet && (reqPath == "" || reqPath == "/") {
			LandingHandler(w, r)
		} else {
			loginPath := strings.TrimSuffix(pathPrefix, "/") + "/login"
			http.Redirect(w, r, loginPath, http.StatusFound)
		}
		return
	}
	expiry, _ := session.Values["token_expiry"].(int64)
	if expiry > 0 && time.Now().Unix() > expiry {
		loginPath := strings.TrimSuffix(viper.GetString("path-prefix"), "/") + "/login"
		http.Redirect(w, r, loginPath, http.StatusFound)
		return
	}
	// Check group authorization if required
	if len(allowedGroups) > 0 {
		isAuthorized, _ := session.Values["is_authorized"].(bool)
		if !isAuthorized {
			RenderErrorPage(w, r, http.StatusForbidden,
				"Access Denied",
				"Your account permissions have changed",
				"Your group membership no longer allows access to this application. Please logout and login again, or contact your administrator.",
				"warning")
			return
		}
	}
	// Add user info to request context for logging
	// Reconstruct claims map from individual session keys
	userLogClaims := make(map[string]string)
	for key, value := range session.Values {
		if keyStr, ok := key.(string); ok && strings.HasPrefix(keyStr, "user_claim_") {
			claimName := strings.TrimPrefix(keyStr, "user_claim_")
			if claimValue, ok := value.(string); ok {
				userLogClaims[claimName] = claimValue
			}
		}
	}
	ctx := context.WithValue(r.Context(), userSubjectKey, userLogClaims)
	next(w, r.WithContext(ctx))
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
		// Use configurable session secret or generate random key
		var sessionKey []byte
		sessionSecret := viper.GetString("session-secret")
		if sessionSecret != "" {
			// Decode hex-encoded session secret
			var err error
			sessionKey, err = hex.DecodeString(sessionSecret)
			if err != nil {
				log.Fatalf("failed to decode session secret (must be hex-encoded): %v", err)
			}
			if len(sessionKey) != sessionKeySize {
				log.Fatalf("session secret must be exactly %d bytes (%d hex characters), got %d bytes", sessionKeySize, sessionKeySize*hexEncodingMultiple, len(sessionKey))
			}
			log.Printf("Using configured session secret")
		} else {
			if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
				log.Fatalf("--session-secret is required in Lambda: random keys are lost across cold starts, logging users out")
			}
			// Generate random session key for development
			sessionKey = make([]byte, sessionKeySize)
			if _, err := rand.Read(sessionKey); err != nil {
				log.Fatalf("failed to generate session key: %v", err)
			}
			log.Printf("Generated random session key (for production, use --session-secret)")
		}
		// Use CookieStore for Lambda deployment, FilesystemStore for regular deployment
		if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
			// Lambda environment - use CookieStore
			sessionStore = sessions.NewCookieStore(sessionKey)
		} else {
			// Regular deployment - use FilesystemStore
			fsStore := sessions.NewFilesystemStore("", sessionKey)
			fsStore.MaxLength(sessionMaxLength)
			sessionStore = fsStore
		}
		pathPrefix := viper.GetString("path-prefix")
		if pathPrefix == "" {
			pathPrefix = "/"
		} else if !strings.HasSuffix(pathPrefix, "/") {
			pathPrefix += "/"
		}

		// Get configurable session max age
		sessionMaxAge := viper.GetInt("session-max-age")

		// Set session options based on store type
		switch store := sessionStore.(type) {
		case *sessions.CookieStore:
			// CookieStore (Lambda)
			store.Options = &sessions.Options{
				Path:     pathPrefix,
				MaxAge:   sessionMaxAge,
				HttpOnly: true,
				Secure:   strings.HasPrefix(oidcRedirectURL, "https://"),
				SameSite: http.SameSiteLaxMode,
			}
		case *sessions.FilesystemStore:
			// FilesystemStore (regular deployment)
			store.Options = &sessions.Options{
				Path:     pathPrefix,
				MaxAge:   sessionMaxAge,
				HttpOnly: true,
				Secure:   strings.HasPrefix(oidcRedirectURL, "https://"),
				SameSite: http.SameSiteLaxMode,
			}
		}
		log.Printf("OIDC session configuration: Path=%s, Secure=%v, MaxAge=%d", pathPrefix, strings.HasPrefix(oidcRedirectURL, "https://"), sessionMaxAge)
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
	rp.HandleFunc("/logout", LogoutHandler).Methods("POST")
	rp.HandleFunc("/callback", CallbackHandler).Methods("GET")

	// Add middleware
	n := negroni.New()
	n.Use(negroni.NewRecovery())
	n.Use(negroni.NewStatic(http.Dir("public")))
	n.Use(&AuthMiddleware{})                              // Auth runs first to add user context
	n.Use(&UserAwareLogger{Logger: log.StandardLogger()}) // Logger runs after auth to access user context
	n.UseHandler(rp)

	server := &http.Server{
		Addr:              ":" + strconv.Itoa(viper.GetInt("port")),
		Handler:           n,
		ReadHeaderTimeout: viper.GetDuration("read-header-timeout"),
	}

	tlsCert := viper.GetString("tls-cert")
	tlsKey := viper.GetString("tls-key")

	if tlsCert != "" {
		log.Infof("Server running on https://localhost:%v%v", viper.GetInt("port"), viper.GetString("path-prefix"))
		log.Fatal(server.ListenAndServeTLS(tlsCert, tlsKey))
	}

	log.Infof("Server running on http://localhost:%v%v", viper.GetInt("port"), viper.GetString("path-prefix"))
	log.Fatal(server.ListenAndServe())
}

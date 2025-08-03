package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/spf13/viper"
)

func TestExtractResourceGroupName(t *testing.T) {
	vmID := "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/myVM"
	got := extractResourceGroupName(vmID)
	want := "myResourceGroup"
	if got != want {
		t.Errorf("extractResourceGroupName(%q) = %q, want %q", vmID, got, want)
	}
}

func TestNormalizeStatus(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"PowerState/running", string(types.InstanceStateNameRunning)},
		{"PowerState/stopped", string(types.InstanceStateNameStopped)},
		{"PowerState/deallocated", string(types.InstanceStateNameStopped)},
		{"PowerState/unknown", string(types.InstanceStateNamePending)},
	}

	for _, tt := range tests {
		if got := normalizeStatus(tt.input); got != tt.want {
			t.Errorf("normalizeStatus(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestHasAllowedGroup(t *testing.T) {
	tests := []struct {
		name          string
		userGroups    []string
		allowedGroups []string
		want          bool
	}{
		{
			name:          "user has allowed group",
			userGroups:    []string{"admin", "users"},
			allowedGroups: []string{"admin", "operators"},
			want:          true,
		},
		{
			name:          "user has no allowed groups",
			userGroups:    []string{"users", "readers"},
			allowedGroups: []string{"admin", "operators"},
			want:          false,
		},
		{
			name:          "empty allowed groups",
			userGroups:    []string{"admin"},
			allowedGroups: []string{},
			want:          false,
		},
		{
			name:          "empty user groups",
			userGroups:    []string{},
			allowedGroups: []string{"admin"},
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set global allowedGroups for testing
			oldAllowedGroups := allowedGroups
			allowedGroups = tt.allowedGroups
			defer func() { allowedGroups = oldAllowedGroups }()

			if got := hasAllowedGroup(tt.userGroups); got != tt.want {
				t.Errorf("hasAllowedGroup(%v) = %v, want %v", tt.userGroups, got, tt.want)
			}
		})
	}
}

func TestLoginHandler(t *testing.T) {
	tests := []struct {
		name         string
		oidcEnabled  bool
		expectedCode int
	}{
		{
			name:         "OIDC disabled redirects to prefix",
			oidcEnabled:  false,
			expectedCode: http.StatusFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldOidcEnabled := oidcEnabled
			oidcEnabled = tt.oidcEnabled
			defer func() { oidcEnabled = oldOidcEnabled }()

			viper.Set("path-prefix", "/test/")

			req, _ := http.NewRequest("GET", "/login", nil)
			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(LoginHandler)

			handler.ServeHTTP(rr, req)

			if status := rr.Code; status != tt.expectedCode {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tt.expectedCode)
			}

			if !tt.oidcEnabled {
				expectedLocation := "/test/"
				if location := rr.Header().Get("Location"); location != expectedLocation {
					t.Errorf("handler returned wrong location: got %v want %v",
						location, expectedLocation)
				}
			}
		})
	}
}

func TestAuthMiddleware(t *testing.T) {
	tests := []struct {
		name        string
		oidcEnabled bool
		path        string
		expectNext  bool
	}{
		{
			name:        "OIDC disabled passes through",
			oidcEnabled: false,
			path:        "/",
			expectNext:  true,
		},
		{
			name:        "login path passes through",
			oidcEnabled: true,
			path:        "/test/login",
			expectNext:  true,
		},
		{
			name:        "callback path passes through",
			oidcEnabled: true,
			path:        "/test/callback",
			expectNext:  true,
		},
		{
			name:        "favicon passes through",
			oidcEnabled: true,
			path:        "/test/favicon.ico",
			expectNext:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldOidcEnabled := oidcEnabled
			oidcEnabled = tt.oidcEnabled
			defer func() { oidcEnabled = oldOidcEnabled }()

			viper.Set("path-prefix", "/test/")

			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
			})

			req, _ := http.NewRequest("GET", tt.path, nil)
			rr := httptest.NewRecorder()

			middleware := AuthMiddleware(next)
			middleware.ServeHTTP(rr, req)

			if nextCalled != tt.expectNext {
				t.Errorf("next handler called = %v, want %v", nextCalled, tt.expectNext)
			}
		})
	}
}

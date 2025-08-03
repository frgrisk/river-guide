# Claude Development Guide for River Guide

This file contains project-specific instructions for Claude when working on River Guide.

## Code Quality and Linting

### Running Linters

Always run linting before committing changes:

```bash
# Run golangci-lint with auto-fix
golangci-lint run --fix

# Build and test
go build ./...
go test ./...
```

### Key Linting Rules

- Use `golangci-lint run --fix` to automatically fix most issues
- Replace string concatenation with `+=` operator: `path += "/"` not `path = path + "/"`
- Use `http.NoBody` instead of `nil` for HTTP request bodies
- Define constants for magic numbers (session timeouts, key sizes, etc.)
- Use proper context key types (custom type, not string)
- Mark unused parameters with `_` prefix
- Follow struct field alignment recommendations
- Always run `npx prettier --write` on modified files

### Testing Requirements

- Always run tests after changes: `go test ./...`
- Add test coverage for new functionality
- Use proper mocking and table-driven tests
- Test both success and error scenarios

## OIDC Implementation

### Security Principles

- Store minimal session data to avoid cookie size limits
- Clear invalid sessions gracefully - redirect to login, don't show technical errors
- Use cryptographically secure random keys
- Validate all configuration parameters together
- Log detailed errors server-side but show friendly messages to users

### Session Management

- Session cookies should be HttpOnly, Secure (for HTTPS), SameSite=Lax
- Store only: `user_groups`, `token_expiry`, `authenticated` flag, and individual claim keys
- Never store full ID tokens in sessions (too large)
- Store claims as individual session keys (e.g., `user_claim_sub`, `user_claim_email`) to avoid gob serialization issues with maps
- Clear corrupted sessions and redirect to login

### Configuration

- All OIDC params (issuer, client-id, client-secret, redirect-url) must be provided together
- Scopes are configurable with sensible defaults
- Only request "groups" scope if group filtering is configured
- Validate redirect URL format for cookie security settings

## Error Handling Patterns

### Session Errors

Use the `clearSessionAndRedirectToLogin()` helper for any session-related errors:

```go
if err != nil {
    clearSessionAndRedirectToLogin(w, r, fmt.Sprintf("Handler: session error: %v", err))
    return
}
```

### User-Friendly Messages

- Log technical details server-side
- Show user-friendly messages in browser
- For OIDC errors, display provider error messages when available
- Clear invalid state gracefully without exposing internals

## Logging

### User-Aware Logging

The application includes user identification in request logs:

- Anonymous: `"GET / -> 200 OK in 5ms"`
- Authenticated: `"GET /toggle user=john.doe@company.com -> 200 OK in 12ms"`

### Context Usage

Add user info to request context for logging:

```go
userSubject, _ := session.Values["user_subject"].(string)
ctx := context.WithValue(r.Context(), userSubjectKey, userSubject)
next.ServeHTTP(w, r.WithContext(ctx))
```

## Development Workflow

### Before Committing

1. Run `golangci-lint run --fix` to fix code quality issues
2. Run `go build ./...` to ensure compilation
3. Run `go test ./...` to ensure tests pass
4. Check that changes work with both AWS and Azure providers
5. Test OIDC flows if authentication code was modified

### Git Practices

- Write descriptive commit messages
- Include "Co-Authored-By: Claude <noreply@anthropic.com>" in commits (though the user's config overrides this)
- Group related changes into single commits
- Test functionality before pushing

## Architecture Notes

### Provider Pattern

- CloudProvider interface supports AWS and Azure
- Each provider handles its own authentication and resource management
- RDS support is optional and AWS-specific

### Middleware Stack

1. Negroni recovery middleware
2. Static file serving
3. UserAwareLogger (custom request logging)
4. AuthMiddleware (OIDC authentication)
5. Router (gorilla/mux)

### Security Considerations

- Session keys are generated using crypto/rand
- Cookie security flags are set based on redirect URL scheme
- Group-based authorization is enforced after authentication
- All session errors result in clean logout and redirect to login

## Common Patterns

### Constants

Define constants for magic numbers:

```go
const (
    sessionKeySize = 32
    sessionMaxAge  = 86400 // 24 hours
)
```

### Context Keys

Use typed context keys:

```go
type contextKey string
const userSubjectKey contextKey = "user_subject"
```

### Error Handling

Always handle errors gracefully and provide user-friendly messages while logging technical details.

### Session Storage

Avoid storing maps in sessions due to gob serialization issues. Store complex data as individual keys:

```go
// Don't do this (gob serialization issues)
session.Values["user_claims"] = map[string]string{"sub": "user123", "email": "user@example.com"}

// Do this instead
session.Values["user_claim_sub"] = "user123"
session.Values["user_claim_email"] = "user@example.com"

// Reconstruct when needed
claims := make(map[string]string)
for key, value := range session.Values {
    if strings.HasPrefix(key, "user_claim_") {
        claimName := strings.TrimPrefix(key, "user_claim_")
        if claimValue, ok := value.(string); ok {
            claims[claimName] = claimValue
        }
    }
}
```

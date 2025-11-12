package auth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// AuthType represents the type of authentication mechanism
type AuthType string

const (
	Bearer AuthType = "bearer"
	Basic  AuthType = "basic"
	APIKey AuthType = "apikey"
	Custom AuthType = "custom"
)

// AuthConfig contains configuration for authentication
type AuthConfig struct {
	Type        AuthType
	Token       string
	Username    string
	Password    string
	KeyName     string
	KeyValue    string
	KeyIn       string // header, query, cookie
	HeaderName  string
	HeaderValue string
}

// Authenticator defines the interface for applying authentication to HTTP requests
type Authenticator interface {
	Apply(req *http.Request) error
	GetHeaders() map[string]string
}

// NewAuthenticator creates an authenticator based on the provided configuration
func NewAuthenticator(config AuthConfig) (Authenticator, error) {
	switch config.Type {
	case Bearer:
		return NewBearerAuth(config.Token), nil
	case Basic:
		return NewBasicAuth(config.Username, config.Password), nil
	case APIKey:
		return NewAPIKeyAuth(config.KeyName, config.KeyValue, config.KeyIn), nil
	case Custom:
		return NewCustomAuth(config.HeaderName, config.HeaderValue), nil
	default:
		return nil, fmt.Errorf("unsupported auth type: %s", config.Type)
	}
}

// BearerAuth implements bearer token authentication
type BearerAuth struct {
	token string
}

// NewBearerAuth creates a new bearer token authenticator
func NewBearerAuth(token string) *BearerAuth {
	return &BearerAuth{token: token}
}

func (b *BearerAuth) Apply(req *http.Request) error {
	if b.token == "" {
		return fmt.Errorf("bearer token is empty")
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	return nil
}

func (b *BearerAuth) GetHeaders() map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + b.token,
	}
}

// BasicAuth implements HTTP basic authentication
type BasicAuth struct {
	username string
	password string
}

// NewBasicAuth creates a new HTTP basic authenticator
func NewBasicAuth(username, password string) *BasicAuth {
	return &BasicAuth{
		username: username,
		password: password,
	}
}

func (b *BasicAuth) Apply(req *http.Request) error {
	if b.username == "" || b.password == "" {
		return fmt.Errorf("username or password is empty")
	}
	auth := b.username + ":" + b.password
	encoded := base64.StdEncoding.EncodeToString([]byte(auth))
	req.Header.Set("Authorization", "Basic "+encoded)
	return nil
}

func (b *BasicAuth) GetHeaders() map[string]string {
	auth := b.username + ":" + b.password
	encoded := base64.StdEncoding.EncodeToString([]byte(auth))
	return map[string]string{
		"Authorization": "Basic " + encoded,
	}
}

// APIKeyAuth implements API key authentication
type APIKeyAuth struct {
	keyName  string
	keyValue string
	keyIn    string
}

// NewAPIKeyAuth creates a new API key authenticator
func NewAPIKeyAuth(keyName, keyValue, keyIn string) *APIKeyAuth {
	if keyIn == "" {
		keyIn = "header"
	}
	return &APIKeyAuth{
		keyName:  keyName,
		keyValue: keyValue,
		keyIn:    keyIn,
	}
}

func (a *APIKeyAuth) Apply(req *http.Request) error {
	if a.keyName == "" || a.keyValue == "" {
		return fmt.Errorf("API key name or value is empty")
	}

	switch strings.ToLower(a.keyIn) {
	case "header":
		req.Header.Set(a.keyName, a.keyValue)
	case "query":
		q := req.URL.Query()
		q.Set(a.keyName, a.keyValue)
		req.URL.RawQuery = q.Encode()
	case "cookie":
		req.AddCookie(&http.Cookie{
			Name:  a.keyName,
			Value: a.keyValue,
		})
	default:
		return fmt.Errorf("unsupported API key location: %s", a.keyIn)
	}

	return nil
}

func (a *APIKeyAuth) GetHeaders() map[string]string {
	if strings.ToLower(a.keyIn) == "header" {
		return map[string]string{
			a.keyName: a.keyValue,
		}
	}
	return map[string]string{}
}

// CustomAuth implements custom header-based authentication
type CustomAuth struct {
	headerName  string
	headerValue string
}

// NewCustomAuth creates a new custom header authenticator
func NewCustomAuth(headerName, headerValue string) *CustomAuth {
	return &CustomAuth{
		headerName:  headerName,
		headerValue: headerValue,
	}
}

func (c *CustomAuth) Apply(req *http.Request) error {
	if c.headerName == "" || c.headerValue == "" {
		return fmt.Errorf("custom header name or value is empty")
	}
	req.Header.Set(c.headerName, c.headerValue)
	return nil
}

func (c *CustomAuth) GetHeaders() map[string]string {
	return map[string]string{
		c.headerName: c.headerValue,
	}
}

// ParseAuthValue parses an authentication value string into an AuthConfig
func ParseAuthValue(authType AuthType, authValue string) (AuthConfig, error) {
	config := AuthConfig{Type: authType}

	switch authType {
	case Bearer:
		config.Token = authValue
	case Basic:
		parts := strings.SplitN(authValue, ":", 2)
		if len(parts) != 2 {
			return config, fmt.Errorf("basic auth value must be in format 'username:password'")
		}
		config.Username = parts[0]
		config.Password = parts[1]
	case APIKey:
		parts := strings.SplitN(authValue, ":", 2)
		if len(parts) != 2 {
			return config, fmt.Errorf("API key value must be in format 'keyName:keyValue'")
		}
		config.KeyName = parts[0]
		config.KeyValue = parts[1]
		config.KeyIn = "header"
	case Custom:
		parts := strings.SplitN(authValue, ":", 2)
		if len(parts) != 2 {
			return config, fmt.Errorf("custom auth value must be in format 'headerName:headerValue'")
		}
		config.HeaderName = parts[0]
		config.HeaderValue = parts[1]
	default:
		return config, fmt.Errorf("unsupported auth type: %s", authType)
	}

	return config, nil
}

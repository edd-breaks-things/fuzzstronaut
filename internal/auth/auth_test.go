package auth

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"
)

func TestNewAuthenticator(t *testing.T) {
	tests := []struct {
		name    string
		config  AuthConfig
		wantErr bool
	}{
		{
			name: "Bearer auth",
			config: AuthConfig{
				Type:  Bearer,
				Token: "test-token",
			},
			wantErr: false,
		},
		{
			name: "Basic auth",
			config: AuthConfig{
				Type:     Basic,
				Username: "user",
				Password: "pass",
			},
			wantErr: false,
		},
		{
			name: "API Key auth",
			config: AuthConfig{
				Type:     APIKey,
				KeyName:  "X-API-Key",
				KeyValue: "key-value",
				KeyIn:    "header",
			},
			wantErr: false,
		},
		{
			name: "Custom auth",
			config: AuthConfig{
				Type:        Custom,
				HeaderName:  "X-Custom",
				HeaderValue: "custom-value",
			},
			wantErr: false,
		},
		{
			name: "Unsupported auth type",
			config: AuthConfig{
				Type: "unsupported",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := NewAuthenticator(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAuthenticator() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && auth == nil {
				t.Error("NewAuthenticator() returned nil authenticator")
			}
		})
	}
}

func TestBearerAuth_Apply(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		wantErr    bool
		wantHeader string
	}{
		{
			name:       "Valid token",
			token:      "test-token-123",
			wantErr:    false,
			wantHeader: "Bearer test-token-123",
		},
		{
			name:    "Empty token",
			token:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewBearerAuth(tt.token)
			req, _ := http.NewRequest("GET", "http://example.com", nil)

			err := auth.Apply(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("BearerAuth.Apply() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				got := req.Header.Get("Authorization")
				if got != tt.wantHeader {
					t.Errorf("BearerAuth.Apply() header = %v, want %v", got, tt.wantHeader)
				}
			}
		})
	}
}

func TestBearerAuth_GetHeaders(t *testing.T) {
	auth := NewBearerAuth("test-token")
	headers := auth.GetHeaders()

	expected := "Bearer test-token"
	if headers["Authorization"] != expected {
		t.Errorf("BearerAuth.GetHeaders() = %v, want %v", headers["Authorization"], expected)
	}
}

func TestBasicAuth_Apply(t *testing.T) {
	tests := []struct {
		name       string
		username   string
		password   string
		wantErr    bool
		wantHeader string
	}{
		{
			name:       "Valid credentials",
			username:   "user",
			password:   "pass",
			wantErr:    false,
			wantHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass")),
		},
		{
			name:     "Empty username",
			username: "",
			password: "pass",
			wantErr:  true,
		},
		{
			name:     "Empty password",
			username: "user",
			password: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewBasicAuth(tt.username, tt.password)
			req, _ := http.NewRequest("GET", "http://example.com", nil)

			err := auth.Apply(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("BasicAuth.Apply() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				got := req.Header.Get("Authorization")
				if got != tt.wantHeader {
					t.Errorf("BasicAuth.Apply() header = %v, want %v", got, tt.wantHeader)
				}
			}
		})
	}
}

func TestBasicAuth_GetHeaders(t *testing.T) {
	auth := NewBasicAuth("user", "pass")
	headers := auth.GetHeaders()

	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
	if headers["Authorization"] != expected {
		t.Errorf("BasicAuth.GetHeaders() = %v, want %v", headers["Authorization"], expected)
	}
}

func TestAPIKeyAuth_Apply(t *testing.T) {
	tests := []struct {
		name      string
		keyName   string
		keyValue  string
		keyIn     string
		wantErr   bool
		checkFunc func(*testing.T, *http.Request)
	}{
		{
			name:     "Header API key",
			keyName:  "X-API-Key",
			keyValue: "secret-key",
			keyIn:    "header",
			wantErr:  false,
			checkFunc: func(t *testing.T, req *http.Request) {
				if got := req.Header.Get("X-API-Key"); got != "secret-key" {
					t.Errorf("Header value = %v, want %v", got, "secret-key")
				}
			},
		},
		{
			name:     "Query API key",
			keyName:  "api_key",
			keyValue: "secret-key",
			keyIn:    "query",
			wantErr:  false,
			checkFunc: func(t *testing.T, req *http.Request) {
				if got := req.URL.Query().Get("api_key"); got != "secret-key" {
					t.Errorf("Query value = %v, want %v", got, "secret-key")
				}
			},
		},
		{
			name:     "Cookie API key",
			keyName:  "session",
			keyValue: "secret-session",
			keyIn:    "cookie",
			wantErr:  false,
			checkFunc: func(t *testing.T, req *http.Request) {
				cookie, err := req.Cookie("session")
				if err != nil {
					t.Errorf("Cookie not found: %v", err)
					return
				}
				if cookie.Value != "secret-session" {
					t.Errorf("Cookie value = %v, want %v", cookie.Value, "secret-session")
				}
			},
		},
		{
			name:     "Default to header",
			keyName:  "X-API-Key",
			keyValue: "secret-key",
			keyIn:    "",
			wantErr:  false,
			checkFunc: func(t *testing.T, req *http.Request) {
				if got := req.Header.Get("X-API-Key"); got != "secret-key" {
					t.Errorf("Header value = %v, want %v", got, "secret-key")
				}
			},
		},
		{
			name:     "Empty key name",
			keyName:  "",
			keyValue: "secret-key",
			keyIn:    "header",
			wantErr:  true,
		},
		{
			name:     "Empty key value",
			keyName:  "X-API-Key",
			keyValue: "",
			keyIn:    "header",
			wantErr:  true,
		},
		{
			name:     "Invalid location",
			keyName:  "X-API-Key",
			keyValue: "secret-key",
			keyIn:    "invalid",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewAPIKeyAuth(tt.keyName, tt.keyValue, tt.keyIn)
			req, _ := http.NewRequest("GET", "http://example.com", nil)

			err := auth.Apply(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("APIKeyAuth.Apply() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, req)
			}
		})
	}
}

func TestAPIKeyAuth_GetHeaders(t *testing.T) {
	tests := []struct {
		name     string
		keyName  string
		keyValue string
		keyIn    string
		want     map[string]string
	}{
		{
			name:     "Header location",
			keyName:  "X-API-Key",
			keyValue: "secret",
			keyIn:    "header",
			want:     map[string]string{"X-API-Key": "secret"},
		},
		{
			name:     "Query location",
			keyName:  "api_key",
			keyValue: "secret",
			keyIn:    "query",
			want:     map[string]string{},
		},
		{
			name:     "Cookie location",
			keyName:  "session",
			keyValue: "secret",
			keyIn:    "cookie",
			want:     map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewAPIKeyAuth(tt.keyName, tt.keyValue, tt.keyIn)
			headers := auth.GetHeaders()

			if len(headers) != len(tt.want) {
				t.Errorf("APIKeyAuth.GetHeaders() returned %d headers, want %d", len(headers), len(tt.want))
			}

			for k, v := range tt.want {
				if headers[k] != v {
					t.Errorf("APIKeyAuth.GetHeaders()[%s] = %v, want %v", k, headers[k], v)
				}
			}
		})
	}
}

func TestCustomAuth_Apply(t *testing.T) {
	tests := []struct {
		name        string
		headerName  string
		headerValue string
		wantErr     bool
	}{
		{
			name:        "Valid custom header",
			headerName:  "X-Custom-Auth",
			headerValue: "custom-value",
			wantErr:     false,
		},
		{
			name:        "Empty header name",
			headerName:  "",
			headerValue: "custom-value",
			wantErr:     true,
		},
		{
			name:        "Empty header value",
			headerName:  "X-Custom-Auth",
			headerValue: "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewCustomAuth(tt.headerName, tt.headerValue)
			req, _ := http.NewRequest("GET", "http://example.com", nil)

			err := auth.Apply(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("CustomAuth.Apply() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				got := req.Header.Get(tt.headerName)
				if got != tt.headerValue {
					t.Errorf("CustomAuth.Apply() header = %v, want %v", got, tt.headerValue)
				}
			}
		})
	}
}

func TestCustomAuth_GetHeaders(t *testing.T) {
	auth := NewCustomAuth("X-Custom", "value")
	headers := auth.GetHeaders()

	if headers["X-Custom"] != "value" {
		t.Errorf("CustomAuth.GetHeaders() = %v, want %v", headers["X-Custom"], "value")
	}
}

func TestParseAuthValue(t *testing.T) {
	tests := []struct {
		name      string
		authType  AuthType
		authValue string
		want      AuthConfig
		wantErr   bool
	}{
		{
			name:      "Bearer token",
			authType:  Bearer,
			authValue: "my-token",
			want: AuthConfig{
				Type:  Bearer,
				Token: "my-token",
			},
			wantErr: false,
		},
		{
			name:      "Basic auth",
			authType:  Basic,
			authValue: "username:password",
			want: AuthConfig{
				Type:     Basic,
				Username: "username",
				Password: "password",
			},
			wantErr: false,
		},
		{
			name:      "Basic auth with colon in password",
			authType:  Basic,
			authValue: "username:pass:word",
			want: AuthConfig{
				Type:     Basic,
				Username: "username",
				Password: "pass:word",
			},
			wantErr: false,
		},
		{
			name:      "Invalid basic auth",
			authType:  Basic,
			authValue: "username",
			wantErr:   true,
		},
		{
			name:      "API key",
			authType:  APIKey,
			authValue: "X-API-Key:secret",
			want: AuthConfig{
				Type:     APIKey,
				KeyName:  "X-API-Key",
				KeyValue: "secret",
				KeyIn:    "header",
			},
			wantErr: false,
		},
		{
			name:      "Invalid API key",
			authType:  APIKey,
			authValue: "invalid",
			wantErr:   true,
		},
		{
			name:      "Custom auth",
			authType:  Custom,
			authValue: "X-Custom:custom-value",
			want: AuthConfig{
				Type:        Custom,
				HeaderName:  "X-Custom",
				HeaderValue: "custom-value",
			},
			wantErr: false,
		},
		{
			name:      "Invalid custom auth",
			authType:  Custom,
			authValue: "invalid",
			wantErr:   true,
		},
		{
			name:      "Unsupported auth type",
			authType:  "invalid",
			authValue: "value",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAuthValue(tt.authType, tt.authValue)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAuthValue() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				if got.Type != tt.want.Type {
					t.Errorf("ParseAuthValue() Type = %v, want %v", got.Type, tt.want.Type)
				}
				if got.Token != tt.want.Token {
					t.Errorf("ParseAuthValue() Token = %v, want %v", got.Token, tt.want.Token)
				}
				if got.Username != tt.want.Username {
					t.Errorf("ParseAuthValue() Username = %v, want %v", got.Username, tt.want.Username)
				}
				if got.Password != tt.want.Password {
					t.Errorf("ParseAuthValue() Password = %v, want %v", got.Password, tt.want.Password)
				}
				if got.KeyName != tt.want.KeyName {
					t.Errorf("ParseAuthValue() KeyName = %v, want %v", got.KeyName, tt.want.KeyName)
				}
				if got.KeyValue != tt.want.KeyValue {
					t.Errorf("ParseAuthValue() KeyValue = %v, want %v", got.KeyValue, tt.want.KeyValue)
				}
				if got.KeyIn != tt.want.KeyIn {
					t.Errorf("ParseAuthValue() KeyIn = %v, want %v", got.KeyIn, tt.want.KeyIn)
				}
				if got.HeaderName != tt.want.HeaderName {
					t.Errorf("ParseAuthValue() HeaderName = %v, want %v", got.HeaderName, tt.want.HeaderName)
				}
				if got.HeaderValue != tt.want.HeaderValue {
					t.Errorf("ParseAuthValue() HeaderValue = %v, want %v", got.HeaderValue, tt.want.HeaderValue)
				}
			}
		})
	}
}

func TestAPIKeyAuth_QueryParameter(t *testing.T) {
	auth := NewAPIKeyAuth("api_key", "secret123", "query")

	// Create request with existing query parameters
	req, _ := http.NewRequest("GET", "http://example.com?existing=param", nil)

	err := auth.Apply(req)
	if err != nil {
		t.Fatalf("APIKeyAuth.Apply() error = %v", err)
	}

	// Parse the URL to check query parameters
	parsedURL, _ := url.Parse(req.URL.String())
	query := parsedURL.Query()

	// Check that the API key was added
	if got := query.Get("api_key"); got != "secret123" {
		t.Errorf("API key in query = %v, want %v", got, "secret123")
	}

	// Check that existing parameters are preserved
	if got := query.Get("existing"); got != "param" {
		t.Errorf("Existing parameter = %v, want %v", got, "param")
	}
}

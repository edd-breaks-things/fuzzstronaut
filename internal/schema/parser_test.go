package schema

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNewParser(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		wantErr  bool
		wantType string
	}{
		{
			name:     "OpenAPI format",
			format:   "openapi",
			wantErr:  false,
			wantType: "*schema.OpenAPIParser",
		},
		{
			name:     "OpenAPI3 format",
			format:   "openapi3",
			wantErr:  false,
			wantType: "*schema.OpenAPIParser",
		},
		{
			name:     "Swagger format",
			format:   "swagger",
			wantErr:  false,
			wantType: "*schema.OpenAPIParser",
		},
		{
			name:     "Custom format",
			format:   "custom",
			wantErr:  false,
			wantType: "*schema.CustomParser",
		},
		{
			name:     "JSON format",
			format:   "json",
			wantErr:  false,
			wantType: "*schema.CustomParser",
		},
		{
			name:     "Case insensitive",
			format:   "OPENAPI",
			wantErr:  false,
			wantType: "*schema.OpenAPIParser",
		},
		{
			name:    "Unsupported format",
			format:  "xml",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser, err := NewParser(tt.format)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewParser() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && parser == nil {
				t.Error("NewParser() returned nil parser")
			}
		})
	}
}

func TestCustomParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "Valid schema",
			input: APISchema{
				Title:   "Test API",
				Version: "1.0",
				BaseURL: "https://api.example.com",
				Endpoints: []Endpoint{
					{
						Path:   "/users",
						Method: "GET",
						Parameters: []EndpointParameter{
							{
								Name: "limit",
								In:   "query",
								Type: "integer",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Missing BaseURL",
			input: APISchema{
				Title:   "Test API",
				Version: "1.0",
				Endpoints: []Endpoint{
					{
						Path:   "/users",
						Method: "GET",
					},
				},
			},
			wantErr: true,
			errMsg:  "baseUrl is required",
		},
		{
			name: "Invalid BaseURL",
			input: APISchema{
				Title:   "Test API",
				Version: "1.0",
				BaseURL: "not a url",
				Endpoints: []Endpoint{
					{
						Path:   "/users",
						Method: "GET",
					},
				},
			},
			wantErr: false, // URL parsing is lenient
		},
		{
			name: "Empty endpoints",
			input: APISchema{
				Title:     "Test API",
				Version:   "1.0",
				BaseURL:   "https://api.example.com",
				Endpoints: []Endpoint{},
			},
			wantErr: true,
			errMsg:  "at least one endpoint is required",
		},
		{
			name: "Missing endpoint path",
			input: APISchema{
				BaseURL: "https://api.example.com",
				Endpoints: []Endpoint{
					{
						Method: "GET",
					},
				},
			},
			wantErr: true,
			errMsg:  "path is required",
		},
		{
			name: "Missing endpoint method",
			input: APISchema{
				BaseURL: "https://api.example.com",
				Endpoints: []Endpoint{
					{
						Path: "/users",
					},
				},
			},
			wantErr: true,
			errMsg:  "method is required",
		},
		{
			name: "Invalid HTTP method",
			input: APISchema{
				BaseURL: "https://api.example.com",
				Endpoints: []Endpoint{
					{
						Path:   "/users",
						Method: "INVALID",
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid method",
		},
		{
			name: "Missing parameter name",
			input: APISchema{
				BaseURL: "https://api.example.com",
				Endpoints: []Endpoint{
					{
						Path:   "/users",
						Method: "GET",
						Parameters: []EndpointParameter{
							{
								In:   "query",
								Type: "string",
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "name is required",
		},
		{
			name: "Missing parameter 'in'",
			input: APISchema{
				BaseURL: "https://api.example.com",
				Endpoints: []Endpoint{
					{
						Path:   "/users",
						Method: "GET",
						Parameters: []EndpointParameter{
							{
								Name: "id",
								Type: "string",
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "'in' is required",
		},
		{
			name: "Invalid parameter 'in'",
			input: APISchema{
				BaseURL: "https://api.example.com",
				Endpoints: []Endpoint{
					{
						Path:   "/users",
						Method: "GET",
						Parameters: []EndpointParameter{
							{
								Name: "id",
								In:   "body", // body is not valid for parameters
								Type: "string",
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid 'in' value",
		},
	}

	parser := NewCustomParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatalf("Failed to marshal test input: %v", err)
			}

			reader := bytes.NewReader(jsonData)
			schema, err := parser.Parse(reader)

			if (err != nil) != tt.wantErr {
				t.Errorf("CustomParser.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("CustomParser.Parse() error = %v, want error containing %v", err, tt.errMsg)
				}
			}

			if !tt.wantErr && schema == nil {
				t.Error("CustomParser.Parse() returned nil schema")
			}
		})
	}
}

func TestCustomParser_ValidateSchema(t *testing.T) {
	parser := NewCustomParser()

	validSchema := APISchema{
		Title:   "Test API",
		Version: "1.0",
		BaseURL: "https://api.example.com",
		Endpoints: []Endpoint{
			{
				Path:   "/users",
				Method: "GET",
			},
		},
	}

	invalidSchema := APISchema{
		Title:   "Test API",
		Version: "1.0",
		// Missing BaseURL
		Endpoints: []Endpoint{
			{
				Path:   "/users",
				Method: "GET",
			},
		},
	}

	t.Run("Valid schema", func(t *testing.T) {
		jsonData, _ := json.Marshal(validSchema)
		reader := bytes.NewReader(jsonData)

		err := parser.ValidateSchema(reader)
		if err != nil {
			t.Errorf("CustomParser.ValidateSchema() error = %v, want nil", err)
		}
	})

	t.Run("Invalid schema", func(t *testing.T) {
		jsonData, _ := json.Marshal(invalidSchema)
		reader := bytes.NewReader(jsonData)

		err := parser.ValidateSchema(reader)
		if err == nil {
			t.Error("CustomParser.ValidateSchema() error = nil, want error")
		}
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		reader := strings.NewReader("not valid json")

		err := parser.ValidateSchema(reader)
		if err == nil {
			t.Error("CustomParser.ValidateSchema() error = nil, want error")
		}
	})
}

func TestDetectSchemaFormat(t *testing.T) {
	tests := []struct {
		name    string
		input   map[string]interface{}
		want    string
		wantErr bool
	}{
		{
			name: "OpenAPI 3.0",
			input: map[string]interface{}{
				"openapi": "3.0.0",
				"info":    map[string]interface{}{},
				"paths":   map[string]interface{}{},
			},
			want:    "openapi",
			wantErr: false,
		},
		{
			name: "Swagger 2.0",
			input: map[string]interface{}{
				"swagger": "2.0",
				"info":    map[string]interface{}{},
				"paths":   map[string]interface{}{},
			},
			want:    "swagger",
			wantErr: false,
		},
		{
			name: "Custom format with endpoints",
			input: map[string]interface{}{
				"title":     "API",
				"endpoints": []interface{}{},
			},
			want:    "custom",
			wantErr: false,
		},
		{
			name: "OpenAPI with paths",
			input: map[string]interface{}{
				"paths": map[string]interface{}{
					"/users": map[string]interface{}{},
				},
			},
			want:    "openapi",
			wantErr: false,
		},
		{
			name: "Unknown format defaults to custom",
			input: map[string]interface{}{
				"something": "else",
			},
			want:    "custom",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatalf("Failed to marshal test input: %v", err)
			}

			reader := bytes.NewReader(jsonData)
			got, err := DetectSchemaFormat(reader)

			if (err != nil) != tt.wantErr {
				t.Errorf("DetectSchemaFormat() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got != tt.want {
				t.Errorf("DetectSchemaFormat() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("Invalid JSON", func(t *testing.T) {
		reader := strings.NewReader("not valid json")
		_, err := DetectSchemaFormat(reader)
		if err == nil {
			t.Error("DetectSchemaFormat() error = nil, want error")
		}
	})
}

func TestValidHTTPMethods(t *testing.T) {
	parser := NewCustomParser()

	validMethods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

	for _, method := range validMethods {
		t.Run(method, func(t *testing.T) {
			schema := APISchema{
				BaseURL: "https://api.example.com",
				Endpoints: []Endpoint{
					{
						Path:   "/test",
						Method: method,
					},
				},
			}

			jsonData, _ := json.Marshal(schema)
			reader := bytes.NewReader(jsonData)

			_, err := parser.Parse(reader)
			if err != nil {
				t.Errorf("Valid method %s rejected: %v", method, err)
			}
		})

		// Test lowercase
		t.Run(method+" lowercase", func(t *testing.T) {
			schema := APISchema{
				BaseURL: "https://api.example.com",
				Endpoints: []Endpoint{
					{
						Path:   "/test",
						Method: strings.ToLower(method),
					},
				},
			}

			jsonData, _ := json.Marshal(schema)
			reader := bytes.NewReader(jsonData)

			_, err := parser.Parse(reader)
			if err != nil {
				t.Errorf("Valid method %s (lowercase) rejected: %v", strings.ToLower(method), err)
			}
		})
	}
}

func TestValidParameterLocations(t *testing.T) {
	parser := NewCustomParser()

	validLocations := []string{"query", "header", "path", "cookie"}

	for _, location := range validLocations {
		t.Run(location, func(t *testing.T) {
			schema := APISchema{
				BaseURL: "https://api.example.com",
				Endpoints: []Endpoint{
					{
						Path:   "/test",
						Method: "GET",
						Parameters: []EndpointParameter{
							{
								Name: "param",
								In:   location,
								Type: "string",
							},
						},
					},
				},
			}

			jsonData, _ := json.Marshal(schema)
			reader := bytes.NewReader(jsonData)

			_, err := parser.Parse(reader)
			if err != nil {
				t.Errorf("Valid parameter location %s rejected: %v", location, err)
			}
		})
	}
}

func TestEndpointWithRequestBody(t *testing.T) {
	parser := NewCustomParser()

	schema := APISchema{
		BaseURL: "https://api.example.com",
		Endpoints: []Endpoint{
			{
				Path:   "/users",
				Method: "POST",
				RequestBody: &RequestBody{
					Required: true,
					Content: map[string]MediaType{
						"application/json": {
							Schema: json.RawMessage(`{"type": "object"}`),
						},
					},
				},
			},
		},
	}

	jsonData, _ := json.Marshal(schema)
	reader := bytes.NewReader(jsonData)

	result, err := parser.Parse(reader)
	if err != nil {
		t.Fatalf("Failed to parse schema with request body: %v", err)
	}

	if result.Endpoints[0].RequestBody == nil {
		t.Error("RequestBody was not preserved")
	}

	if !result.Endpoints[0].RequestBody.Required {
		t.Error("RequestBody.Required was not preserved")
	}
}

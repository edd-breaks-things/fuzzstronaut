package schema

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// EndpointParameter represents a parameter for an API endpoint
type EndpointParameter struct {
	Name      string        `json:"name"`
	In        string        `json:"in"`
	Required  bool          `json:"required"`
	Type      string        `json:"type"`
	Format    string        `json:"format,omitempty"`
	Default   interface{}   `json:"default,omitempty"`
	Example   interface{}   `json:"example,omitempty"`
	Minimum   *float64      `json:"minimum,omitempty"`
	Maximum   *float64      `json:"maximum,omitempty"`
	MinLength *int          `json:"minLength,omitempty"`
	MaxLength *int          `json:"maxLength,omitempty"`
	Pattern   string        `json:"pattern,omitempty"`
	Enum      []interface{} `json:"enum,omitempty"`
}

// RequestBody represents the request body specification for an endpoint
type RequestBody struct {
	Required bool                 `json:"required"`
	Content  map[string]MediaType `json:"content"`
}

// MediaType represents a media type with its schema and example
type MediaType struct {
	Schema  json.RawMessage `json:"schema"`
	Example interface{}     `json:"example,omitempty"`
}

// Endpoint represents an API endpoint with its parameters and responses
type Endpoint struct {
	Path        string                `json:"path"`
	Method      string                `json:"method"`
	OperationID string                `json:"operationId,omitempty"`
	Summary     string                `json:"summary,omitempty"`
	Parameters  []EndpointParameter   `json:"parameters"`
	RequestBody *RequestBody          `json:"requestBody,omitempty"`
	Responses   map[string]Response   `json:"responses"`
	Security    []map[string][]string `json:"security,omitempty"`
}

// Response represents an API response specification
type Response struct {
	Description string               `json:"description"`
	Content     map[string]MediaType `json:"content,omitempty"`
}

// APISchema represents the complete API schema structure
type APISchema struct {
	Title       string              `json:"title"`
	Version     string              `json:"version"`
	BaseURL     string              `json:"baseUrl"`
	Endpoints   []Endpoint          `json:"endpoints"`
	SecurityDef map[string]Security `json:"securityDefinitions,omitempty"`
}

// Security represents a security definition for the API
type Security struct {
	Type        string `json:"type"`
	Scheme      string `json:"scheme,omitempty"`
	In          string `json:"in,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// Parser defines the interface for parsing API schemas
type Parser interface {
	Parse(reader io.Reader) (*APISchema, error)
	ValidateSchema(reader io.Reader) error
}

// NewParser creates a parser for the specified schema format
func NewParser(format string) (Parser, error) {
	switch strings.ToLower(format) {
	case "openapi", "openapi3", "swagger":
		return NewOpenAPIParser(), nil
	case "custom", "json":
		return NewCustomParser(), nil
	default:
		return nil, fmt.Errorf("unsupported schema format: %s", format)
	}
}

// CustomParser implements parsing for custom JSON schema format
type CustomParser struct{}

// NewCustomParser creates a parser for custom JSON schema format
func NewCustomParser() *CustomParser {
	return &CustomParser{}
}

func (p *CustomParser) Parse(reader io.Reader) (*APISchema, error) {
	var schema APISchema
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&schema); err != nil {
		return nil, fmt.Errorf("failed to parse custom schema: %w", err)
	}

	if err := p.validateParsedSchema(&schema); err != nil {
		return nil, err
	}

	return &schema, nil
}

func (p *CustomParser) ValidateSchema(reader io.Reader) error {
	_, err := p.Parse(reader)
	return err
}

func (p *CustomParser) validateParsedSchema(schema *APISchema) error {
	if schema.BaseURL == "" {
		return fmt.Errorf("baseUrl is required")
	}

	if _, err := url.Parse(schema.BaseURL); err != nil {
		return fmt.Errorf("invalid baseUrl: %w", err)
	}

	if len(schema.Endpoints) == 0 {
		return fmt.Errorf("at least one endpoint is required")
	}

	for i, endpoint := range schema.Endpoints {
		if endpoint.Path == "" {
			return fmt.Errorf("endpoint %d: path is required", i)
		}
		if endpoint.Method == "" {
			return fmt.Errorf("endpoint %d: method is required", i)
		}

		method := strings.ToUpper(endpoint.Method)
		validMethods := map[string]bool{
			"GET": true, "POST": true, "PUT": true, "PATCH": true,
			"DELETE": true, "HEAD": true, "OPTIONS": true,
		}
		if !validMethods[method] {
			return fmt.Errorf("endpoint %d: invalid method %s", i, endpoint.Method)
		}

		for j, param := range endpoint.Parameters {
			if param.Name == "" {
				return fmt.Errorf("endpoint %d, parameter %d: name is required", i, j)
			}
			if param.In == "" {
				return fmt.Errorf("endpoint %d, parameter %d: 'in' is required", i, j)
			}

			validIn := map[string]bool{
				"query": true, "header": true, "path": true, "cookie": true,
			}
			if !validIn[param.In] {
				return fmt.Errorf("endpoint %d, parameter %d: invalid 'in' value %s", i, j, param.In)
			}
		}
	}

	return nil
}

// DetectSchemaFormat detects the format of an API schema from its content
func DetectSchemaFormat(reader io.Reader) (string, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}

	var jsonData map[string]interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}

	if _, hasOpenAPI := jsonData["openapi"]; hasOpenAPI {
		return "openapi", nil
	}

	if _, hasSwagger := jsonData["swagger"]; hasSwagger {
		return "swagger", nil
	}

	if _, hasEndpoints := jsonData["endpoints"]; hasEndpoints {
		return "custom", nil
	}

	if paths, hasPaths := jsonData["paths"]; hasPaths {
		if _, isMap := paths.(map[string]interface{}); isMap {
			return "openapi", nil
		}
	}

	return "custom", nil
}

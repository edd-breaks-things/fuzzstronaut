package schema

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

type OpenAPIParser struct {
	loader *openapi3.Loader
}

func NewOpenAPIParser() *OpenAPIParser {
	return &OpenAPIParser{
		loader: openapi3.NewLoader(),
	}
}

func (p *OpenAPIParser) Parse(reader io.Reader) (*APISchema, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read schema: %w", err)
	}

	doc, err := p.loader.LoadFromData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to load OpenAPI document: %w", err)
	}

	if err := doc.Validate(context.Background()); err != nil {
		return nil, fmt.Errorf("invalid OpenAPI document: %w", err)
	}

	return p.convertToAPISchema(doc)
}

func (p *OpenAPIParser) ValidateSchema(reader io.Reader) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read schema: %w", err)
	}

	doc, err := p.loader.LoadFromData(data)
	if err != nil {
		return fmt.Errorf("failed to load OpenAPI document: %w", err)
	}

	return doc.Validate(context.Background())
}

func (p *OpenAPIParser) convertToAPISchema(doc *openapi3.T) (*APISchema, error) {
	schema := &APISchema{
		Title:       doc.Info.Title,
		Version:     doc.Info.Version,
		Endpoints:   []Endpoint{},
		SecurityDef: make(map[string]Security),
	}

	if err := p.extractBaseURL(doc, schema); err != nil {
		return nil, fmt.Errorf("failed to extract base URL: %w", err)
	}

	p.extractSecurityDefinitions(doc, schema)

	if err := p.extractEndpoints(doc, schema); err != nil {
		return nil, fmt.Errorf("failed to extract endpoints: %w", err)
	}

	return schema, nil
}

func (p *OpenAPIParser) extractBaseURL(doc *openapi3.T, schema *APISchema) error {
	if len(doc.Servers) > 0 {
		serverURL := doc.Servers[0].URL

		for name, variable := range doc.Servers[0].Variables {
			if variable.Default != "" {
				serverURL = strings.ReplaceAll(serverURL, "{"+name+"}", variable.Default)
			}
		}

		if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
			serverURL = "https://" + serverURL
		}

		if _, err := url.Parse(serverURL); err != nil {
			return fmt.Errorf("invalid server URL: %w", err)
		}

		schema.BaseURL = serverURL
	} else {
		schema.BaseURL = "http://localhost"
	}

	return nil
}

func (p *OpenAPIParser) extractSecurityDefinitions(doc *openapi3.T, schema *APISchema) {
	if doc.Components == nil || doc.Components.SecuritySchemes == nil {
		return
	}

	for name, secScheme := range doc.Components.SecuritySchemes {
		if secScheme.Value == nil {
			continue
		}

		sec := Security{
			Type:        string(secScheme.Value.Type),
			Description: secScheme.Value.Description,
		}

		switch secScheme.Value.Type {
		case "http":
			sec.Scheme = secScheme.Value.Scheme
		case "apiKey":
			sec.In = string(secScheme.Value.In)
			sec.Name = secScheme.Value.Name
		default:
			// Other security scheme types (oauth2, openIdConnect) are not currently handled
		}

		schema.SecurityDef[name] = sec
	}
}

func (p *OpenAPIParser) extractEndpoints(doc *openapi3.T, schema *APISchema) error {
	for path, pathItem := range doc.Paths.Map() {
		if pathItem == nil {
			continue
		}

		operations := map[string]*openapi3.Operation{
			"GET":     pathItem.Get,
			"POST":    pathItem.Post,
			"PUT":     pathItem.Put,
			"PATCH":   pathItem.Patch,
			"DELETE":  pathItem.Delete,
			"HEAD":    pathItem.Head,
			"OPTIONS": pathItem.Options,
		}

		for method, operation := range operations {
			if operation == nil {
				continue
			}

			endpoint := Endpoint{
				Path:        path,
				Method:      method,
				OperationID: operation.OperationID,
				Summary:     operation.Summary,
				Parameters:  []EndpointParameter{},
				Responses:   make(map[string]Response),
			}

			p.extractParameters(operation, pathItem.Parameters, &endpoint)
			p.extractRequestBody(operation, &endpoint)
			p.extractResponses(operation, &endpoint)
			p.extractSecurity(operation, doc.Security, &endpoint)

			schema.Endpoints = append(schema.Endpoints, endpoint)
		}
	}

	return nil
}

func (p *OpenAPIParser) extractParameters(operation *openapi3.Operation, pathParams openapi3.Parameters, endpoint *Endpoint) {
	allParams := append(pathParams, operation.Parameters...)

	for _, paramRef := range allParams {
		if paramRef.Value == nil {
			continue
		}

		param := paramRef.Value
		epParam := EndpointParameter{
			Name:     param.Name,
			In:       param.In,
			Required: param.Required,
		}

		if param.Schema != nil && param.Schema.Value != nil {
			schema := param.Schema.Value
			if schema.Type != nil && len(*schema.Type) > 0 {
				epParam.Type = (*schema.Type)[0]
			}
			epParam.Format = schema.Format
			epParam.Default = schema.Default
			epParam.Example = schema.Example
			epParam.Pattern = schema.Pattern

			if schema.Min != nil {
				epParam.Minimum = schema.Min
			}
			if schema.Max != nil {
				epParam.Maximum = schema.Max
			}
			if schema.MinLength > 0 {
				minLen := int(schema.MinLength)
				epParam.MinLength = &minLen
			}
			if schema.MaxLength != nil {
				maxLen := int(*schema.MaxLength)
				epParam.MaxLength = &maxLen
			}
			if len(schema.Enum) > 0 {
				epParam.Enum = schema.Enum
			}
		}

		endpoint.Parameters = append(endpoint.Parameters, epParam)
	}
}

func (p *OpenAPIParser) extractRequestBody(operation *openapi3.Operation, endpoint *Endpoint) {
	if operation.RequestBody == nil || operation.RequestBody.Value == nil {
		return
	}

	rb := operation.RequestBody.Value
	reqBody := &RequestBody{
		Required: rb.Required,
		Content:  make(map[string]MediaType),
	}

	for contentType, mediaType := range rb.Content {
		if mediaType.Schema != nil {
			schemaJSON, _ := mediaType.Schema.MarshalJSON()
			reqBody.Content[contentType] = MediaType{
				Schema:  schemaJSON,
				Example: mediaType.Example,
			}
		}
	}

	endpoint.RequestBody = reqBody
}

func (p *OpenAPIParser) extractResponses(operation *openapi3.Operation, endpoint *Endpoint) {
	if operation.Responses == nil {
		return
	}

	for status, responseRef := range operation.Responses.Map() {
		if responseRef.Value == nil {
			continue
		}

		resp := responseRef.Value
		response := Response{
			Description: *resp.Description,
			Content:     make(map[string]MediaType),
		}

		for contentType, mediaType := range resp.Content {
			if mediaType.Schema != nil {
				schemaJSON, _ := mediaType.Schema.MarshalJSON()
				response.Content[contentType] = MediaType{
					Schema:  schemaJSON,
					Example: mediaType.Example,
				}
			}
		}

		endpoint.Responses[status] = response
	}
}

func (p *OpenAPIParser) extractSecurity(operation *openapi3.Operation, globalSecurity openapi3.SecurityRequirements, endpoint *Endpoint) {
	security := operation.Security
	if security == nil {
		security = &globalSecurity
	}

	if security != nil && len(*security) > 0 {
		endpoint.Security = make([]map[string][]string, len(*security))
		for i, req := range *security {
			endpoint.Security[i] = req
		}
	}
}

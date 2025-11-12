package fuzzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/edd-breaks-things/fuzzstronaut/internal/logger"
	"github.com/edd-breaks-things/fuzzstronaut/internal/schema"
	"go.uber.org/zap"
)

// FuzzConfig contains configuration for the fuzzing engine
type FuzzConfig struct {
	TargetURL     string
	Schema        *schema.APISchema
	Workers       int
	RateLimit     int
	Timeout       time.Duration
	MaxIterations int
	Strategies    []MutationStrategy
	Headers       map[string]string
	AuthHeader    string
	AuthValue     string
	Verbose       bool
}

// FuzzResult represents the result of a single fuzz test
type FuzzResult struct {
	Endpoint      string
	Method        string
	StatusCode    int
	ResponseTime  time.Duration
	Payload       interface{}
	Response      []byte
	Error         error
	Anomaly       bool
	AnomalyReason string
	Timestamp     time.Time
}

// Engine is the main fuzzing engine that coordinates testing
type Engine struct {
	config    *FuzzConfig
	mutator   *Mutator
	client    *http.Client
	results   chan FuzzResult
	semaphore chan struct{}
	rateLimit <-chan time.Time
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewEngine creates a new fuzzing engine with the provided configuration
func NewEngine(config *FuzzConfig) *Engine {
	strategies := config.Strategies
	if len(strategies) == 0 {
		strategies = []MutationStrategy{
			BoundaryValues,
			TypeConfusion,
			SQLInjection,
			XSSPayloads,
			RandomMutation,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Engine{
		config:  config,
		mutator: NewMutator(strategies),
		client: &http.Client{
			Timeout: config.Timeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		results:   make(chan FuzzResult, config.Workers*10),
		semaphore: make(chan struct{}, config.Workers),
		rateLimit: time.Tick(time.Second / time.Duration(config.RateLimit)),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start begins the fuzzing campaign and returns a channel of results
func (e *Engine) Start() <-chan FuzzResult {
	logger.Info("Starting fuzzing engine",
		zap.String("target", e.config.TargetURL),
		zap.Int("workers", e.config.Workers),
		zap.Int("rate_limit", e.config.RateLimit),
		zap.Int("endpoints", len(e.config.Schema.Endpoints)))
	go e.run()
	return e.results
}

// Stop gracefully stops the fuzzing engine
func (e *Engine) Stop() {
	logger.Info("Stopping fuzzing engine")
	e.cancel()
	e.wg.Wait()
	// Don't close results here - run() will do it
	logger.Info("Fuzzing engine stopped")
}

func (e *Engine) run() {
	defer close(e.results)

	for _, endpoint := range e.config.Schema.Endpoints {
		select {
		case <-e.ctx.Done():
			return
		default:
			e.fuzzEndpoint(endpoint)
		}
	}

	e.wg.Wait()
}

func (e *Engine) fuzzEndpoint(endpoint schema.Endpoint) {
	logger.Debug("Fuzzing endpoint",
		zap.String("path", endpoint.Path),
		zap.String("method", endpoint.Method))
	testCases := e.generateTestCases(endpoint)
	
	// Log mutation strategies being used when verbose
	if e.config.Verbose {
		logger.Debug("🧪 Generating test cases",
			zap.String("endpoint", fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path)),
			zap.Int("count", len(testCases)),
			zap.Any("strategies", e.config.Strategies))
		
		// Log sample payloads for first few test cases
		for i, tc := range testCases {
			if i >= 3 {
				break // Only show first 3 examples
			}
			logger.Debug("  Sample test case",
				zap.Int("index", i+1),
				zap.Any("parameters", tc.Parameters),
				zap.Any("body", tc.Body))
		}
	} else {
		logger.Debugf("Generated %d test cases for %s %s", len(testCases), endpoint.Method, endpoint.Path)
	}

	for _, testCase := range testCases {
		select {
		case <-e.ctx.Done():
			return
		case e.semaphore <- struct{}{}:
			e.wg.Add(1)
			go func(tc TestCase) {
				defer e.wg.Done()
				defer func() { <-e.semaphore }()

				<-e.rateLimit

				result := e.executeTestCase(tc)
				if result.Anomaly {
					logger.Warn("Anomaly detected",
						zap.String("endpoint", result.Endpoint),
						zap.String("method", result.Method),
						zap.Int("status", result.StatusCode),
						zap.String("reason", result.AnomalyReason))
				}

				// Check if context is cancelled before sending
				select {
				case <-e.ctx.Done():
					return
				case e.results <- result:
				}
			}(testCase)
		}
	}
}

// TestCase represents a single test case with parameters and payload
type TestCase struct {
	Endpoint   schema.Endpoint
	Parameters map[string]interface{}
	Body       interface{}
	Headers    map[string]string
}

func (e *Engine) generateTestCases(endpoint schema.Endpoint) []TestCase {
	testCases := []TestCase{}

	baseCase := TestCase{
		Endpoint:   endpoint,
		Parameters: make(map[string]interface{}),
		Headers:    make(map[string]string),
	}

	for k, v := range e.config.Headers {
		baseCase.Headers[k] = v
	}

	for _, param := range endpoint.Parameters {
		mutations := e.mutator.Mutate(param.Default, param.Type)
		for _, mutation := range mutations {
			tc := e.cloneTestCase(baseCase)
			tc.Parameters[param.Name] = mutation
			testCases = append(testCases, tc)
		}
	}

	if endpoint.RequestBody != nil {
		for contentType, mediaType := range endpoint.RequestBody.Content {
			if strings.Contains(contentType, "json") {
				bodyMutations := e.generateJSONBodyMutations(mediaType.Schema)
				for _, mutation := range bodyMutations {
					tc := e.cloneTestCase(baseCase)
					tc.Body = mutation
					tc.Headers["Content-Type"] = contentType
					testCases = append(testCases, tc)
				}
			}
		}
	}

	if len(testCases) == 0 {
		testCases = append(testCases, baseCase)
	}

	return testCases
}

func (e *Engine) generateJSONBodyMutations(schemaData json.RawMessage) []interface{} {
	mutations := []interface{}{}

	var schema map[string]interface{}
	if err := json.Unmarshal(schemaData, &schema); err != nil {
		return mutations
	}

	sampleData := e.generateSampleFromSchema(schema)

	if jsonBytes, err := json.Marshal(sampleData); err == nil {
		mutatedJSONs := e.mutator.MutateJSON(jsonBytes)
		for _, mutatedJSON := range mutatedJSONs {
			var mutatedData interface{}
			if err := json.Unmarshal(mutatedJSON, &mutatedData); err == nil {
				mutations = append(mutations, mutatedData)
			} else {
				mutations = append(mutations, string(mutatedJSON))
			}
		}
	}

	return mutations
}

func (e *Engine) generateSampleFromSchema(schema map[string]interface{}) interface{} {
	if schemaType, ok := schema["type"].(string); ok {
		switch schemaType {
		case "object":
			obj := make(map[string]interface{})
			if properties, ok := schema["properties"].(map[string]interface{}); ok {
				for key, propSchema := range properties {
					if propMap, ok := propSchema.(map[string]interface{}); ok {
						obj[key] = e.generateSampleFromSchema(propMap)
					}
				}
			}
			return obj
		case "array":
			if items, ok := schema["items"].(map[string]interface{}); ok {
				return []interface{}{e.generateSampleFromSchema(items)}
			}
			return []interface{}{}
		case "string":
			if example, ok := schema["example"].(string); ok {
				return example
			}
			return "test"
		case "integer":
			if example, ok := schema["example"].(float64); ok {
				return int(example)
			}
			return 42
		case "number":
			if example, ok := schema["example"].(float64); ok {
				return example
			}
			return 3.14
		case "boolean":
			return true
		}
	}

	return nil
}

func (e *Engine) cloneTestCase(tc TestCase) TestCase {
	newTC := TestCase{
		Endpoint:   tc.Endpoint,
		Parameters: make(map[string]interface{}),
		Headers:    make(map[string]string),
		Body:       tc.Body,
	}

	for k, v := range tc.Parameters {
		newTC.Parameters[k] = v
	}

	for k, v := range tc.Headers {
		newTC.Headers[k] = v
	}

	return newTC
}

func (e *Engine) executeTestCase(tc TestCase) FuzzResult {
	result := FuzzResult{
		Endpoint:  tc.Endpoint.Path,
		Method:    tc.Endpoint.Method,
		Payload:   tc.Body,
		Timestamp: time.Now(),
	}

	// Create a context with timeout for this specific request
	ctx, cancel := context.WithTimeout(e.ctx, e.config.Timeout)
	defer cancel()

	req, err := e.buildRequestWithContext(ctx, tc)
	if err != nil {
		logger.Error("Failed to build request",
			zap.String("endpoint", tc.Endpoint.Path),
			zap.String("method", tc.Endpoint.Method),
			zap.Error(err))
		result.Error = err
		return result
	}

	if e.config.AuthHeader != "" && e.config.AuthValue != "" {
		req.Header.Set(e.config.AuthHeader, e.config.AuthValue)
	}

	// Log detailed request information when verbose
	if e.config.Verbose {
		logger.Debug("🚀 Sending fuzzing request",
			zap.String("method", req.Method),
			zap.String("url", req.URL.String()),
			zap.Any("headers", req.Header),
			zap.Any("query_params", tc.Parameters),
			zap.Any("body_payload", tc.Body))
	}

	startTime := time.Now()
	resp, err := e.client.Do(req)
	result.ResponseTime = time.Since(startTime)

	if err != nil {
		logger.Debug("Request failed",
			zap.String("endpoint", tc.Endpoint.Path),
			zap.String("method", tc.Endpoint.Method),
			zap.Error(err))
		result.Error = err
		return result
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	result.StatusCode = resp.StatusCode

	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	result.Response = buf.Bytes()

	// Log response details when verbose
	if e.config.Verbose {
		responsePreview := string(result.Response)
		if len(responsePreview) > 500 {
			responsePreview = responsePreview[:500] + "... (truncated)"
		}
		logger.Debug("📨 Response received",
			zap.Int("status_code", result.StatusCode),
			zap.Duration("response_time", result.ResponseTime),
			zap.Int("response_size", len(result.Response)),
			zap.String("response_preview", responsePreview))
	}

	result.Anomaly, result.AnomalyReason = e.detectAnomaly(result)

	return result
}

func (e *Engine) buildRequestWithContext(ctx context.Context, tc TestCase) (*http.Request, error) {
	targetURL := e.config.TargetURL
	if !strings.HasSuffix(targetURL, "/") && !strings.HasPrefix(tc.Endpoint.Path, "/") {
		targetURL += "/"
	}
	targetURL += tc.Endpoint.Path

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %w", err)
	}

	q := parsedURL.Query()
	for _, param := range tc.Endpoint.Parameters {
		switch param.In {
		case "query":
			if value, ok := tc.Parameters[param.Name]; ok {
				q.Set(param.Name, fmt.Sprintf("%v", value))
			}
		case "path":
			path := strings.ReplaceAll(parsedURL.Path, "{"+param.Name+"}", fmt.Sprintf("%v", tc.Parameters[param.Name]))
			parsedURL.Path = path
		}
	}
	parsedURL.RawQuery = q.Encode()

	var bodyReader *bytes.Reader
	if tc.Body != nil {
		bodyBytes, err := json.Marshal(tc.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		
		// Log the actual JSON payload being sent when verbose
		if e.config.Verbose && len(bodyBytes) > 0 {
			logger.Debug("📦 Request body JSON",
				zap.String("raw_json", string(bodyBytes)))
		}
		
		bodyReader = bytes.NewReader(bodyBytes)
	} else {
		bodyReader = bytes.NewReader([]byte{})
	}

	req, err := http.NewRequestWithContext(ctx, tc.Endpoint.Method, parsedURL.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	for key, value := range tc.Headers {
		req.Header.Set(key, value)
	}

	for _, param := range tc.Endpoint.Parameters {
		if param.In == "header" {
			if value, ok := tc.Parameters[param.Name]; ok {
				req.Header.Set(param.Name, fmt.Sprintf("%v", value))
			}
		}
	}

	return req, nil
}

func (e *Engine) detectAnomaly(result FuzzResult) (bool, string) {
	if result.Error != nil {
		return true, fmt.Sprintf("Request error: %v", result.Error)
	}

	if result.StatusCode >= 500 {
		return true, fmt.Sprintf("Server error: %d", result.StatusCode)
	}

	if result.ResponseTime > e.config.Timeout/2 {
		return true, fmt.Sprintf("Slow response: %v", result.ResponseTime)
	}

	responseStr := string(result.Response)

	errorIndicators := []string{
		"stack trace",
		"exception",
		"error in",
		"fatal error",
		"uncaught",
		"syntax error",
		"undefined index",
		"null pointer",
		"internal server error",
		"database error",
		"mysql",
		"postgresql",
		"sqlite",
		"oracle error",
		"sql syntax",
	}

	for _, indicator := range errorIndicators {
		if strings.Contains(strings.ToLower(responseStr), indicator) {
			return true, fmt.Sprintf("Error disclosure: found '%s'", indicator)
		}
	}

	if len(result.Response) > 1000000 {
		return true, "Unusually large response"
	}

	if len(result.Response) == 0 && result.StatusCode == 200 {
		return true, "Empty response with 200 status"
	}

	return false, ""
}

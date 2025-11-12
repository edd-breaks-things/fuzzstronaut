package fuzzer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/edd-breaks-things/fuzzstronaut/internal/schema"
)

func TestNewEngine(t *testing.T) {
	config := &FuzzConfig{
		TargetURL: "https://api.example.com",
		Schema: &schema.APISchema{
			Endpoints: []schema.Endpoint{
				{
					Path:   "/test",
					Method: "GET",
				},
			},
		},
		Workers:   5,
		RateLimit: 10,
		Timeout:   5 * time.Second,
	}

	engine := NewEngine(config)

	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}

	if engine.config != config {
		t.Error("Engine config mismatch")
	}

	if engine.mutator == nil {
		t.Error("Engine mutator is nil")
	}

	if engine.client == nil {
		t.Error("Engine client is nil")
	}

	if engine.ctx == nil {
		t.Error("Engine context is nil")
	}

	if engine.cancel == nil {
		t.Error("Engine cancel func is nil")
	}
}

func TestNewEngine_DefaultStrategies(t *testing.T) {
	config := &FuzzConfig{
		TargetURL: "https://api.example.com",
		Schema:    &schema.APISchema{},
		Workers:   5,
		RateLimit: 10,
		Timeout:   5 * time.Second,
		// No strategies specified - should use defaults
	}

	engine := NewEngine(config)

	if engine.mutator == nil {
		t.Fatal("Mutator is nil")
	}

	// Should have default strategies
	if len(engine.mutator.strategies) == 0 {
		t.Error("No default strategies were set")
	}
}

func TestEngine_StartStop(t *testing.T) {
	config := &FuzzConfig{
		TargetURL: "https://api.example.com",
		Schema: &schema.APISchema{
			Endpoints: []schema.Endpoint{
				{
					Path:   "/test",
					Method: "GET",
				},
			},
		},
		Workers:   2,
		RateLimit: 100,
		Timeout:   1 * time.Second,
	}

	engine := NewEngine(config)
	results := engine.Start()

	// Verify results channel is returned
	if results == nil {
		t.Fatal("Start() returned nil results channel")
	}

	// Stop the engine
	engine.Stop()

	// Verify results channel is closed
	select {
	case _, ok := <-results:
		if ok {
			t.Error("Results channel should be closed after Stop()")
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for channel to close")
	}
}

func TestEngine_ExecuteTestCase(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request properties
		if r.Header.Get("X-Custom") != "value" {
			t.Errorf("Expected custom header not found")
		}

		// Return different responses based on path
		switch r.URL.Path {
		case "/success":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok"}`))
		case "/error":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "internal server error"}`))
		case "/slow":
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	config := &FuzzConfig{
		TargetURL: server.URL,
		Schema:    &schema.APISchema{},
		Workers:   1,
		RateLimit: 100,
		Timeout:   1 * time.Second,
		Headers: map[string]string{
			"X-Custom": "value",
		},
	}

	engine := NewEngine(config)

	tests := []struct {
		name           string
		testCase       TestCase
		wantStatusCode int
		wantAnomaly    bool
	}{
		{
			name: "Successful request",
			testCase: TestCase{
				Endpoint: schema.Endpoint{
					Path:   "/success",
					Method: "GET",
				},
				Headers: map[string]string{
					"X-Custom": "value",
				},
			},
			wantStatusCode: 200,
			wantAnomaly:    false,
		},
		{
			name: "Server error",
			testCase: TestCase{
				Endpoint: schema.Endpoint{
					Path:   "/error",
					Method: "GET",
				},
				Headers: map[string]string{
					"X-Custom": "value",
				},
			},
			wantStatusCode: 500,
			wantAnomaly:    true,
		},
		{
			name: "Not found",
			testCase: TestCase{
				Endpoint: schema.Endpoint{
					Path:   "/notfound",
					Method: "GET",
				},
				Headers: map[string]string{
					"X-Custom": "value",
				},
			},
			wantStatusCode: 404,
			wantAnomaly:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.executeTestCase(tt.testCase)

			if result.StatusCode != tt.wantStatusCode {
				t.Errorf("StatusCode = %v, want %v", result.StatusCode, tt.wantStatusCode)
			}

			if result.Anomaly != tt.wantAnomaly {
				t.Errorf("Anomaly = %v, want %v", result.Anomaly, tt.wantAnomaly)
			}

			if result.Endpoint != tt.testCase.Endpoint.Path {
				t.Errorf("Endpoint = %v, want %v", result.Endpoint, tt.testCase.Endpoint.Path)
			}

			if result.Method != tt.testCase.Endpoint.Method {
				t.Errorf("Method = %v, want %v", result.Method, tt.testCase.Endpoint.Method)
			}
		})
	}
}

func TestEngine_GenerateTestCases(t *testing.T) {
	config := &FuzzConfig{
		TargetURL: "https://api.example.com",
		Schema:    &schema.APISchema{},
		Workers:   1,
		RateLimit: 100,
		Timeout:   1 * time.Second,
		Headers: map[string]string{
			"X-Global": "global-value",
		},
	}

	engine := NewEngine(config)

	endpoint := schema.Endpoint{
		Path:   "/users/{id}",
		Method: "GET",
		Parameters: []schema.EndpointParameter{
			{
				Name:     "id",
				In:       "path",
				Required: true,
				Type:     "string",
				Default:  "123",
			},
			{
				Name:     "filter",
				In:       "query",
				Required: false,
				Type:     "string",
				Default:  "active",
			},
		},
	}

	testCases := engine.generateTestCases(endpoint)

	if len(testCases) == 0 {
		t.Fatal("No test cases generated")
	}

	// Check that global headers are included
	for _, tc := range testCases {
		if tc.Headers["X-Global"] != "global-value" {
			t.Error("Global header not included in test case")
		}

		// Verify endpoint is set
		if tc.Endpoint.Path != endpoint.Path {
			t.Errorf("Test case endpoint path = %v, want %v", tc.Endpoint.Path, endpoint.Path)
		}
	}
}

func TestEngine_GenerateJSONBodyMutations(t *testing.T) {
	config := &FuzzConfig{
		TargetURL: "https://api.example.com",
		Schema:    &schema.APISchema{},
		Workers:   1,
		RateLimit: 100,
		Timeout:   1 * time.Second,
	}

	engine := NewEngine(config)

	jsonSchema := []byte(`{
		"type": "object",
		"properties": {
			"name": {"type": "string", "example": "John"},
			"age": {"type": "integer", "example": 30},
			"active": {"type": "boolean"}
		}
	}`)

	mutations := engine.generateJSONBodyMutations(jsonSchema)

	if len(mutations) == 0 {
		t.Error("No JSON mutations generated")
	}

	// Verify mutations are valid JSON or strings
	for _, mutation := range mutations {
		if mutation == nil {
			t.Error("Nil mutation generated")
		}
	}
}

func TestEngine_GenerateSampleFromSchema(t *testing.T) {
	config := &FuzzConfig{
		TargetURL: "https://api.example.com",
		Schema:    &schema.APISchema{},
		Workers:   1,
		RateLimit: 100,
		Timeout:   1 * time.Second,
	}

	engine := NewEngine(config)

	tests := []struct {
		name   string
		schema map[string]interface{}
		check  func(interface{}) bool
	}{
		{
			name: "Object schema",
			schema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"name": map[string]interface{}{
						"type":    "string",
						"example": "test",
					},
				},
			},
			check: func(v interface{}) bool {
				obj, ok := v.(map[string]interface{})
				return ok && obj != nil
			},
		},
		{
			name: "Array schema",
			schema: map[string]interface{}{
				"type": "array",
				"items": map[string]interface{}{
					"type": "string",
				},
			},
			check: func(v interface{}) bool {
				arr, ok := v.([]interface{})
				return ok && arr != nil
			},
		},
		{
			name: "String schema",
			schema: map[string]interface{}{
				"type":    "string",
				"example": "hello",
			},
			check: func(v interface{}) bool {
				str, ok := v.(string)
				return ok && str == "hello"
			},
		},
		{
			name: "Integer schema",
			schema: map[string]interface{}{
				"type":    "integer",
				"example": float64(42),
			},
			check: func(v interface{}) bool {
				num, ok := v.(int)
				return ok && num == 42
			},
		},
		{
			name: "Boolean schema",
			schema: map[string]interface{}{
				"type": "boolean",
			},
			check: func(v interface{}) bool {
				_, ok := v.(bool)
				return ok
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sample := engine.generateSampleFromSchema(tt.schema)
			if !tt.check(sample) {
				t.Errorf("Generated sample does not match expected type: %v", sample)
			}
		})
	}
}

func TestEngine_CloneTestCase(t *testing.T) {
	config := &FuzzConfig{
		TargetURL: "https://api.example.com",
		Schema:    &schema.APISchema{},
		Workers:   1,
		RateLimit: 100,
		Timeout:   1 * time.Second,
	}

	engine := NewEngine(config)

	original := TestCase{
		Endpoint: schema.Endpoint{
			Path:   "/test",
			Method: "GET",
		},
		Parameters: map[string]interface{}{
			"param1": "value1",
			"param2": 42,
		},
		Headers: map[string]string{
			"Header1": "value1",
			"Header2": "value2",
		},
		Body: map[string]interface{}{
			"field": "value",
		},
	}

	cloned := engine.cloneTestCase(original)

	// Verify all fields are copied
	if cloned.Endpoint.Path != original.Endpoint.Path {
		t.Error("Endpoint path not cloned correctly")
	}

	if cloned.Endpoint.Method != original.Endpoint.Method {
		t.Error("Endpoint method not cloned correctly")
	}

	// Verify maps are deep copied
	if len(cloned.Parameters) != len(original.Parameters) {
		t.Error("Parameters not cloned correctly")
	}

	if len(cloned.Headers) != len(original.Headers) {
		t.Error("Headers not cloned correctly")
	}

	// Modify cloned maps to ensure they're independent
	cloned.Parameters["param3"] = "new"
	if _, exists := original.Parameters["param3"]; exists {
		t.Error("Parameters map not deep copied")
	}

	cloned.Headers["Header3"] = "new"
	if _, exists := original.Headers["Header3"]; exists {
		t.Error("Headers map not deep copied")
	}
}

func TestEngine_BuildRequestWithContext(t *testing.T) {
	config := &FuzzConfig{
		TargetURL: "https://api.example.com",
		Schema:    &schema.APISchema{},
		Workers:   1,
		RateLimit: 100,
		Timeout:   1 * time.Second,
	}

	engine := NewEngine(config)
	ctx := context.Background()

	testCase := TestCase{
		Endpoint: schema.Endpoint{
			Path:   "/users/{id}",
			Method: "POST",
			Parameters: []schema.EndpointParameter{
				{
					Name: "id",
					In:   "path",
				},
				{
					Name: "filter",
					In:   "query",
				},
				{
					Name: "X-API-Key",
					In:   "header",
				},
			},
		},
		Parameters: map[string]interface{}{
			"id":        "123",
			"filter":    "active",
			"X-API-Key": "secret",
		},
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: map[string]interface{}{
			"name": "test",
		},
	}

	req, err := engine.buildRequestWithContext(ctx, testCase)
	if err != nil {
		t.Fatalf("buildRequestWithContext() error: %v", err)
	}

	// Verify method
	if req.Method != "POST" {
		t.Errorf("Method = %v, want POST", req.Method)
	}

	// Verify path parameter substitution
	if !contains(req.URL.Path, "123") {
		t.Error("Path parameter not substituted")
	}

	// Verify query parameter
	if req.URL.Query().Get("filter") != "active" {
		t.Error("Query parameter not set correctly")
	}

	// Verify headers
	if req.Header.Get("Content-Type") != "application/json" {
		t.Error("Content-Type header not set")
	}

	if req.Header.Get("X-API-Key") != "secret" {
		t.Error("Header parameter not set")
	}

	// Verify context is set
	if req.Context() != ctx {
		t.Error("Context not set on request")
	}
}

func TestEngine_DetectAnomaly(t *testing.T) {
	config := &FuzzConfig{
		TargetURL: "https://api.example.com",
		Schema:    &schema.APISchema{},
		Workers:   1,
		RateLimit: 100,
		Timeout:   2 * time.Second,
	}

	engine := NewEngine(config)

	tests := []struct {
		name        string
		result      FuzzResult
		wantAnomaly bool
		checkReason func(string) bool
	}{
		{
			name: "Server error",
			result: FuzzResult{
				StatusCode: 500,
			},
			wantAnomaly: true,
			checkReason: func(reason string) bool {
				return contains(reason, "Server error")
			},
		},
		{
			name: "Slow response",
			result: FuzzResult{
				StatusCode:   200,
				ResponseTime: 1500 * time.Millisecond,
			},
			wantAnomaly: true,
			checkReason: func(reason string) bool {
				return contains(reason, "Slow response")
			},
		},
		{
			name: "Error disclosure",
			result: FuzzResult{
				StatusCode: 200,
				Response:   []byte("Fatal error: Uncaught exception at line 42"),
			},
			wantAnomaly: true,
			checkReason: func(reason string) bool {
				return contains(reason, "Error disclosure")
			},
		},
		{
			name: "SQL error",
			result: FuzzResult{
				StatusCode: 200,
				Response:   []byte("MySQL error: syntax error near SELECT"),
			},
			wantAnomaly: true,
			checkReason: func(reason string) bool {
				return contains(reason, "Error disclosure")
			},
		},
		{
			name: "Large response",
			result: FuzzResult{
				StatusCode: 200,
				Response:   make([]byte, 2000000), // 2MB
			},
			wantAnomaly: true,
			checkReason: func(reason string) bool {
				return contains(reason, "large response")
			},
		},
		{
			name: "Empty 200 response",
			result: FuzzResult{
				StatusCode: 200,
				Response:   []byte{},
			},
			wantAnomaly: true,
			checkReason: func(reason string) bool {
				return contains(reason, "Empty response")
			},
		},
		{
			name: "Normal response",
			result: FuzzResult{
				StatusCode:   200,
				Response:     []byte(`{"status": "ok"}`),
				ResponseTime: 100 * time.Millisecond,
			},
			wantAnomaly: false,
		},
		{
			name: "Request error",
			result: FuzzResult{
				Error: context.DeadlineExceeded,
			},
			wantAnomaly: true,
			checkReason: func(reason string) bool {
				return contains(reason, "Request error")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			anomaly, reason := engine.detectAnomaly(tt.result)

			if anomaly != tt.wantAnomaly {
				t.Errorf("detectAnomaly() anomaly = %v, want %v", anomaly, tt.wantAnomaly)
			}

			if tt.wantAnomaly && tt.checkReason != nil {
				if !tt.checkReason(reason) {
					t.Errorf("detectAnomaly() reason = %v, check failed", reason)
				}
			}
		})
	}
}

func TestEngine_ConcurrentExecution(t *testing.T) {
	// Create a test server that counts requests
	requestCount := 0
	mu := &sync.Mutex{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	config := &FuzzConfig{
		TargetURL: server.URL,
		Schema: &schema.APISchema{
			Endpoints: []schema.Endpoint{
				{
					Path:   "/test1",
					Method: "GET",
				},
				{
					Path:   "/test2",
					Method: "POST",
				},
			},
		},
		Workers:   3,
		RateLimit: 100,
		Timeout:   1 * time.Second,
	}

	engine := NewEngine(config)
	results := engine.Start()

	// Collect some results
	collectedResults := []FuzzResult{}
	timeout := time.After(2 * time.Second)

	collecting := true
	for collecting {
		select {
		case result, ok := <-results:
			if !ok {
				collecting = false
				break
			}
			collectedResults = append(collectedResults, result)
			if len(collectedResults) >= 10 {
				collecting = false
			}
		case <-timeout:
			collecting = false
		}
	}

	engine.Stop()

	// Verify we got results
	if len(collectedResults) == 0 {
		t.Error("No results collected from concurrent execution")
	}

	// Verify multiple endpoints were tested
	endpoints := make(map[string]bool)
	for _, result := range collectedResults {
		endpoints[result.Endpoint] = true
	}

	if len(endpoints) < 2 {
		t.Error("Not all endpoints were tested in concurrent execution")
	}
}

// Helper function
func contains(s string, substr string) bool {
	return strings.Contains(s, substr)
}

func TestEngine_RateLimit(t *testing.T) {
	requestTimes := []time.Time{}
	mu := &sync.Mutex{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestTimes = append(requestTimes, time.Now())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Set rate limit to 10 requests per second
	config := &FuzzConfig{
		TargetURL: server.URL,
		Schema: &schema.APISchema{
			Endpoints: []schema.Endpoint{
				{
					Path:   "/test",
					Method: "GET",
					Parameters: []schema.EndpointParameter{
						{
							Name:    "param",
							In:      "query",
							Type:    "string",
							Default: "test",
						},
					},
				},
			},
		},
		Workers:    2,
		RateLimit:  10,
		Timeout:    1 * time.Second,
		Strategies: []MutationStrategy{BoundaryValues}, // Use single strategy for predictable count
	}

	engine := NewEngine(config)
	results := engine.Start()

	// Let it run for a short time
	time.Sleep(500 * time.Millisecond)
	engine.Stop()

	// Drain results
	for range results {
	}

	// Check that rate limiting is working
	mu.Lock()
	defer mu.Unlock()

	if len(requestTimes) == 0 {
		t.Skip("No requests were made")
	}

	// Calculate actual rate
	if len(requestTimes) > 1 {
		duration := requestTimes[len(requestTimes)-1].Sub(requestTimes[0])
		actualRate := float64(len(requestTimes)-1) / duration.Seconds()

		// Allow some variance due to timing
		if actualRate > 15 { // 50% higher than configured rate
			t.Errorf("Rate limit exceeded: actual rate %.2f req/s, limit was 10 req/s", actualRate)
		}
	}
}

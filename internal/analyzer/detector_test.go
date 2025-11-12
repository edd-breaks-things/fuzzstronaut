package analyzer

import (
	"strings"
	"testing"
	"time"
)

func TestNewDetector(t *testing.T) {
	tests := []struct {
		name   string
		config DetectorConfig
		want   DetectorConfig
	}{
		{
			name:   "Default configuration",
			config: DetectorConfig{},
			want: DetectorConfig{
				SlowResponseThreshold: 5 * time.Second,
				LargeResponseSize:     1024 * 1024,
			},
		},
		{
			name: "Custom configuration",
			config: DetectorConfig{
				SlowResponseThreshold: 10 * time.Second,
				LargeResponseSize:     2 * 1024 * 1024,
			},
			want: DetectorConfig{
				SlowResponseThreshold: 10 * time.Second,
				LargeResponseSize:     2 * 1024 * 1024,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := NewDetector(tt.config)
			if detector == nil {
				t.Fatal("NewDetector returned nil")
			}

			if detector.config.SlowResponseThreshold != tt.want.SlowResponseThreshold {
				t.Errorf("SlowResponseThreshold = %v, want %v",
					detector.config.SlowResponseThreshold, tt.want.SlowResponseThreshold)
			}

			if detector.config.LargeResponseSize != tt.want.LargeResponseSize {
				t.Errorf("LargeResponseSize = %v, want %v",
					detector.config.LargeResponseSize, tt.want.LargeResponseSize)
			}

			if detector.patterns == nil {
				t.Error("patterns map is nil")
			}

			if detector.baseline == nil {
				t.Error("baseline is nil")
			}
		})
	}
}

func TestDetector_Analyze_ServerError(t *testing.T) {
	detector := NewDetector(DetectorConfig{})

	tests := []struct {
		name        string
		statusCode  int
		wantAnomaly bool
	}{
		{"500 Internal Server Error", 500, true},
		{"502 Bad Gateway", 502, true},
		{"503 Service Unavailable", 503, true},
		{"200 OK", 200, false},
		{"404 Not Found", 404, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Analyze(tt.statusCode, nil, []byte("test"), time.Second)

			hasServerError := false
			for _, anomaly := range result.Anomalies {
				if anomaly.Type == ServerError {
					hasServerError = true
					break
				}
			}

			if hasServerError != tt.wantAnomaly {
				t.Errorf("Server error detection = %v, want %v", hasServerError, tt.wantAnomaly)
			}
		})
	}
}

func TestDetector_Analyze_ErrorDisclosure(t *testing.T) {
	detector := NewDetector(DetectorConfig{})

	tests := []struct {
		name        string
		body        string
		wantAnomaly bool
	}{
		{
			name:        "Stack trace in response",
			body:        "Error: Stack trace:\n at function() line 42",
			wantAnomaly: true,
		},
		{
			name:        "Exception with details",
			body:        "Fatal Exception at MyClass.method()",
			wantAnomaly: true,
		},
		{
			name:        "Syntax error",
			body:        "PHP Parse error: syntax error, unexpected T_STRING",
			wantAnomaly: true,
		},
		{
			name:        "Debug mode enabled",
			body:        "Debug=true, showing detailed errors",
			wantAnomaly: true,
		},
		{
			name:        "Normal response",
			body:        "Welcome to our API",
			wantAnomaly: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Analyze(200, nil, []byte(tt.body), time.Second)

			hasErrorDisclosure := false
			for _, anomaly := range result.Anomalies {
				if anomaly.Type == ErrorDisclosure {
					hasErrorDisclosure = true
					if anomaly.Evidence == "" && tt.wantAnomaly {
						t.Error("Evidence is empty for error disclosure")
					}
					break
				}
			}

			if hasErrorDisclosure != tt.wantAnomaly {
				t.Errorf("Error disclosure detection = %v, want %v", hasErrorDisclosure, tt.wantAnomaly)
			}
		})
	}
}

func TestDetector_Analyze_SQLInjection(t *testing.T) {
	detector := NewDetector(DetectorConfig{})

	tests := []struct {
		name        string
		body        string
		wantAnomaly bool
	}{
		{
			name:        "MySQL error",
			body:        "You have an error in your SQL syntax near 'SELECT *'",
			wantAnomaly: true,
		},
		{
			name:        "Oracle error",
			body:        "ORA-01756: quoted string not properly terminated",
			wantAnomaly: true,
		},
		{
			name:        "PostgreSQL error",
			body:        "PostgreSQL error: syntax error at or near",
			wantAnomaly: true,
		},
		{
			name:        "Unknown column",
			body:        "Unknown column 'users' in field list",
			wantAnomaly: true,
		},
		{
			name:        "Normal response",
			body:        "Query executed successfully",
			wantAnomaly: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Analyze(200, nil, []byte(tt.body), time.Second)

			hasSQLInjection := false
			for _, anomaly := range result.Anomalies {
				if anomaly.Type == SQLInjection {
					hasSQLInjection = true
					if anomaly.Severity != "CRITICAL" {
						t.Errorf("SQL injection severity = %v, want CRITICAL", anomaly.Severity)
					}
					break
				}
			}

			if hasSQLInjection != tt.wantAnomaly {
				t.Errorf("SQL injection detection = %v, want %v", hasSQLInjection, tt.wantAnomaly)
			}
		})
	}
}

func TestDetector_Analyze_XSS(t *testing.T) {
	detector := NewDetector(DetectorConfig{})

	tests := []struct {
		name        string
		body        string
		wantAnomaly bool
	}{
		{
			name:        "Script tag with alert",
			body:        `<script>alert('XSS')</script>`,
			wantAnomaly: true,
		},
		{
			name:        "JavaScript URL",
			body:        `<a href="javascript:alert(1)">Click</a>`,
			wantAnomaly: true,
		},
		{
			name:        "Event handler",
			body:        `<img src=x onerror="alert('XSS')">`,
			wantAnomaly: true,
		},
		{
			name:        "Document cookie access",
			body:        `<script>document.cookie</script>`,
			wantAnomaly: true,
		},
		{
			name:        "Safe HTML",
			body:        `<div>Normal content</div>`,
			wantAnomaly: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Analyze(200, nil, []byte(tt.body), time.Second)

			hasXSS := false
			for _, anomaly := range result.Anomalies {
				if anomaly.Type == XSSVulnerability {
					hasXSS = true
					break
				}
			}

			if hasXSS != tt.wantAnomaly {
				t.Errorf("XSS detection = %v, want %v", hasXSS, tt.wantAnomaly)
			}
		})
	}
}

func TestDetector_Analyze_PathTraversal(t *testing.T) {
	detector := NewDetector(DetectorConfig{})

	tests := []struct {
		name        string
		body        string
		wantAnomaly bool
	}{
		{
			name:        "etc/passwd content",
			body:        "root:x:0:0:root:/root:/bin/bash",
			wantAnomaly: true,
		},
		{
			name:        "Windows system path",
			body:        "Directory of C:\\Windows\\system32",
			wantAnomaly: true,
		},
		{
			name:        "Boot loader",
			body:        "[boot loader] timeout=30",
			wantAnomaly: true,
		},
		{
			name:        "Normal response",
			body:        "File uploaded successfully",
			wantAnomaly: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Analyze(200, nil, []byte(tt.body), time.Second)

			hasPathTraversal := false
			for _, anomaly := range result.Anomalies {
				if anomaly.Type == PathTraversal {
					hasPathTraversal = true
					break
				}
			}

			if hasPathTraversal != tt.wantAnomaly {
				t.Errorf("Path traversal detection = %v, want %v", hasPathTraversal, tt.wantAnomaly)
			}
		})
	}
}

func TestDetector_Analyze_SlowResponse(t *testing.T) {
	config := DetectorConfig{
		SlowResponseThreshold: 2 * time.Second,
	}
	detector := NewDetector(config)

	tests := []struct {
		name         string
		responseTime time.Duration
		wantAnomaly  bool
	}{
		{"Fast response", 500 * time.Millisecond, false},
		{"Normal response", 1 * time.Second, false},
		{"Slow response", 3 * time.Second, true},
		{"Very slow response", 10 * time.Second, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Analyze(200, nil, []byte("test"), tt.responseTime)

			hasSlowResponse := false
			for _, anomaly := range result.Anomalies {
				if anomaly.Type == SlowResponse {
					hasSlowResponse = true
					break
				}
			}

			if hasSlowResponse != tt.wantAnomaly {
				t.Errorf("Slow response detection = %v, want %v", hasSlowResponse, tt.wantAnomaly)
			}
		})
	}
}

func TestDetector_Analyze_LargeResponse(t *testing.T) {
	config := DetectorConfig{
		LargeResponseSize: 1000,
	}
	detector := NewDetector(config)

	tests := []struct {
		name        string
		body        []byte
		wantAnomaly bool
	}{
		{"Small response", make([]byte, 100), false},
		{"Normal response", make([]byte, 500), false},
		{"Large response", make([]byte, 1001), true},
		{"Very large response", make([]byte, 10000), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Analyze(200, nil, tt.body, time.Second)

			hasLargeResponse := false
			for _, anomaly := range result.Anomalies {
				if anomaly.Type == LargeResponse {
					hasLargeResponse = true
					break
				}
			}

			if hasLargeResponse != tt.wantAnomaly {
				t.Errorf("Large response detection = %v, want %v", hasLargeResponse, tt.wantAnomaly)
			}
		})
	}
}

func TestDetector_Analyze_EmptyResponse(t *testing.T) {
	detector := NewDetector(DetectorConfig{})

	tests := []struct {
		name        string
		statusCode  int
		body        []byte
		wantAnomaly bool
	}{
		{"Empty 200 response", 200, []byte{}, true},
		{"Empty 201 response", 201, []byte{}, false},
		{"Non-empty 200 response", 200, []byte("content"), false},
		{"Empty 404 response", 404, []byte{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Analyze(tt.statusCode, nil, tt.body, time.Second)

			hasEmptyResponse := false
			for _, anomaly := range result.Anomalies {
				if anomaly.Type == EmptyResponse {
					hasEmptyResponse = true
					break
				}
			}

			if hasEmptyResponse != tt.wantAnomaly {
				t.Errorf("Empty response detection = %v, want %v", hasEmptyResponse, tt.wantAnomaly)
			}
		})
	}
}

func TestDetector_CheckSecurityHeaders(t *testing.T) {
	detector := NewDetector(DetectorConfig{})

	tests := []struct {
		name        string
		headers     map[string][]string
		wantAnomaly bool
	}{
		{
			name: "All security headers present",
			headers: map[string][]string{
				"X-Frame-Options":           {"DENY"},
				"X-Content-Type-Options":    {"nosniff"},
				"X-XSS-Protection":          {"1; mode=block"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"Content-Security-Policy":   {"default-src 'self'"},
			},
			wantAnomaly: false,
		},
		{
			name:        "Missing all security headers",
			headers:     map[string][]string{},
			wantAnomaly: true,
		},
		{
			name: "Missing some security headers",
			headers: map[string][]string{
				"X-Frame-Options": {"DENY"},
			},
			wantAnomaly: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Analyze(200, tt.headers, []byte("test"), time.Second)

			hasSecurityHeaderAnomaly := false
			for _, anomaly := range result.Anomalies {
				if anomaly.Type == SecurityHeader {
					hasSecurityHeaderAnomaly = true
					break
				}
			}

			if hasSecurityHeaderAnomaly != tt.wantAnomaly {
				t.Errorf("Security header anomaly = %v, want %v", hasSecurityHeaderAnomaly, tt.wantAnomaly)
			}
		})
	}
}

func TestDetector_CheckJSONErrors(t *testing.T) {
	detector := NewDetector(DetectorConfig{})

	tests := []struct {
		name        string
		body        string
		wantAnomaly bool
	}{
		{
			name:        "JSON with error field",
			body:        `{"error": "Something went wrong"}`,
			wantAnomaly: true,
		},
		{
			name:        "JSON with exception field",
			body:        `{"exception": "NullPointerException"}`,
			wantAnomaly: true,
		},
		{
			name:        "JSON with stacktrace",
			body:        `{"stacktrace": "at line 42"}`,
			wantAnomaly: true,
		},
		{
			name:        "Normal JSON response",
			body:        `{"status": "success", "data": {}}`,
			wantAnomaly: false,
		},
		{
			name:        "Empty error field",
			body:        `{"error": ""}`,
			wantAnomaly: false,
		},
		{
			name:        "False debug field",
			body:        `{"debug": false}`,
			wantAnomaly: false,
		},
		{
			name:        "Invalid JSON",
			body:        `not json`,
			wantAnomaly: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Analyze(200, nil, []byte(tt.body), time.Second)

			hasJSONError := false
			for _, anomaly := range result.Anomalies {
				if anomaly.Type == ErrorDisclosure && strings.Contains(anomaly.Description, "JSON") {
					hasJSONError = true
					break
				}
			}

			if hasJSONError != tt.wantAnomaly {
				t.Errorf("JSON error detection = %v, want %v", hasJSONError, tt.wantAnomaly)
			}
		})
	}
}

func TestDetector_GetSeverity(t *testing.T) {
	detector := NewDetector(DetectorConfig{})

	tests := []struct {
		anomalyType AnomalyType
		want        string
	}{
		{SQLInjection, "CRITICAL"},
		{CommandInjection, "CRITICAL"},
		{XSSVulnerability, "HIGH"},
		{PathTraversal, "HIGH"},
		{ServerError, "HIGH"},
		{ErrorDisclosure, "MEDIUM"},
		{EmptyResponse, "MEDIUM"},
		{SlowResponse, "LOW"},
		{LargeResponse, "LOW"},
		{SecurityHeader, "LOW"},
		{AnomalyType("unknown"), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(string(tt.anomalyType), func(t *testing.T) {
			got := detector.getSeverity(tt.anomalyType)
			if got != tt.want {
				t.Errorf("getSeverity(%v) = %v, want %v", tt.anomalyType, got, tt.want)
			}
		})
	}
}

func TestDetector_GetConfidence(t *testing.T) {
	detector := NewDetector(DetectorConfig{})

	tests := []struct {
		name          string
		anomalyType   AnomalyType
		matchCount    int
		minConfidence float64
	}{
		{"Server error single match", ServerError, 1, 1.0},
		{"SQL injection single match", SQLInjection, 1, 0.9},
		{"XSS multiple matches", XSSVulnerability, 3, 0.85},
		{"Error disclosure multiple", ErrorDisclosure, 5, 0.7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confidence := detector.getConfidence(tt.anomalyType, tt.matchCount)
			if confidence < tt.minConfidence {
				t.Errorf("getConfidence(%v, %d) = %v, want >= %v",
					tt.anomalyType, tt.matchCount, confidence, tt.minConfidence)
			}
			if confidence > 1.0 {
				t.Errorf("confidence exceeds 1.0: %v", confidence)
			}
		})
	}
}

func TestDetector_CalculateRiskScore(t *testing.T) {
	detector := NewDetector(DetectorConfig{})

	tests := []struct {
		name      string
		anomalies []Anomaly
		minScore  float64
		maxScore  float64
	}{
		{
			name:      "No anomalies",
			anomalies: []Anomaly{},
			minScore:  0.0,
			maxScore:  0.0,
		},
		{
			name: "Single critical anomaly",
			anomalies: []Anomaly{
				{Severity: "CRITICAL", Confidence: 1.0},
			},
			minScore: 0.9,
			maxScore: 1.0,
		},
		{
			name: "Multiple low severity",
			anomalies: []Anomaly{
				{Severity: "LOW", Confidence: 0.5},
				{Severity: "LOW", Confidence: 0.6},
			},
			minScore: 0.0,
			maxScore: 0.3,
		},
		{
			name: "Mixed severities",
			anomalies: []Anomaly{
				{Severity: "HIGH", Confidence: 0.8},
				{Severity: "MEDIUM", Confidence: 0.7},
				{Severity: "LOW", Confidence: 0.5},
			},
			minScore: 0.3,
			maxScore: 0.7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := detector.calculateRiskScore(tt.anomalies)
			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("calculateRiskScore() = %v, want between %v and %v",
					score, tt.minScore, tt.maxScore)
			}
		})
	}
}

func TestDetector_UpdateBaseline(t *testing.T) {
	detector := NewDetector(DetectorConfig{})

	// Initial baseline should be empty
	if detector.baseline.AverageResponseTime != 0 {
		t.Error("Initial average response time should be 0")
	}

	// Update baseline multiple times
	detector.UpdateBaseline(200, 100*time.Millisecond, 1000)
	detector.UpdateBaseline(200, 200*time.Millisecond, 2000)
	detector.UpdateBaseline(404, 150*time.Millisecond, 1500)

	// Check status code counts
	if detector.baseline.CommonStatusCodes[200] != 2 {
		t.Errorf("Status 200 count = %v, want 2", detector.baseline.CommonStatusCodes[200])
	}
	if detector.baseline.CommonStatusCodes[404] != 1 {
		t.Errorf("Status 404 count = %v, want 1", detector.baseline.CommonStatusCodes[404])
	}

	// Check averages are updated
	if detector.baseline.AverageResponseTime == 0 {
		t.Error("Average response time not updated")
	}
	if detector.baseline.AverageSize == 0 {
		t.Error("Average size not updated")
	}
}

func TestDetector_IsAnomalousBasedOnBaseline(t *testing.T) {
	detector := NewDetector(DetectorConfig{})

	// Setup baseline
	for i := 0; i < 10; i++ {
		detector.UpdateBaseline(200, 100*time.Millisecond, 1000)
	}
	detector.UpdateBaseline(201, 100*time.Millisecond, 1000)
	detector.UpdateBaseline(204, 100*time.Millisecond, 1000)

	tests := []struct {
		name         string
		statusCode   int
		responseTime time.Duration
		responseSize int
		wantAnomaly  bool
	}{
		{"Normal status and timing", 200, 100 * time.Millisecond, 1000, false},
		{"Unknown status code", 500, 100 * time.Millisecond, 1000, true},
		{"Slow response", 200, 500 * time.Millisecond, 1000, true},
		{"Large response", 200, 100 * time.Millisecond, 20000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			anomalous := detector.IsAnomalousBasedOnBaseline(tt.statusCode, tt.responseTime, tt.responseSize)
			if anomalous != tt.wantAnomaly {
				t.Errorf("IsAnomalousBasedOnBaseline() = %v, want %v", anomalous, tt.wantAnomaly)
			}
		})
	}
}

func TestTruncateEvidence(t *testing.T) {
	tests := []struct {
		evidence string
		maxLen   int
		want     string
	}{
		{"short", 10, "short"},
		{"exactlength", 11, "exactlength"},
		{"this is a very long string", 10, "this is a ..."},
		{"", 10, ""},
	}

	for _, tt := range tests {
		t.Run(tt.evidence, func(t *testing.T) {
			got := truncateEvidence(tt.evidence, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncateEvidence(%q, %d) = %q, want %q",
					tt.evidence, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestMin(t *testing.T) {
	tests := []struct {
		a, b float64
		want float64
	}{
		{1.0, 2.0, 1.0},
		{2.0, 1.0, 1.0},
		{1.5, 1.5, 1.5},
		{-1.0, 1.0, -1.0},
		{0.0, 0.1, 0.0},
	}

	for _, tt := range tests {
		got := min(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("min(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

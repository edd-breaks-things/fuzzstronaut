package reporter

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/edd-breaks-things/fuzzstronaut/internal/fuzzer"
)

func TestNewReporter(t *testing.T) {
	tests := []struct {
		name    string
		config  ReporterConfig
		wantErr bool
	}{
		{
			name: "Valid configuration",
			config: ReporterConfig{
				OutputFile:   "test.json",
				OutputFormat: "json",
				Verbose:      false,
				LogLevel:     "info",
			},
			wantErr: false,
		},
		{
			name: "Invalid log level defaults to info",
			config: ReporterConfig{
				OutputFile:   "test.json",
				OutputFormat: "json",
				LogLevel:     "invalid",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reporter, err := NewReporter(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewReporter() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && reporter == nil {
				t.Error("NewReporter() returned nil reporter")
			}
		})
	}
}

func TestReporter_AddResult(t *testing.T) {
	config := ReporterConfig{
		OutputFile:   "test.json",
		OutputFormat: "json",
		LogLevel:     "info",
	}

	reporter, err := NewReporter(config)
	if err != nil {
		t.Fatalf("Failed to create reporter: %v", err)
	}

	// Add multiple results
	results := []fuzzer.FuzzResult{
		{
			Endpoint:     "/api/users",
			Method:       "GET",
			StatusCode:   200,
			ResponseTime: 100 * time.Millisecond,
		},
		{
			Endpoint:      "/api/posts",
			Method:        "POST",
			StatusCode:    500,
			ResponseTime:  200 * time.Millisecond,
			Error:         nil,
			Anomaly:       true,
			AnomalyReason: "Server error",
		},
	}

	for _, result := range results {
		reporter.AddResult(result)
	}

	// Verify results were added
	if len(reporter.results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(reporter.results))
	}

	// Verify anomalies were tracked
	anomalyCount := 0
	for _, result := range reporter.results {
		if result.Anomaly {
			anomalyCount++
		}
	}
	if anomalyCount != 1 {
		t.Errorf("Expected 1 anomaly, got %d", anomalyCount)
	}
}

func TestReporter_GenerateReport(t *testing.T) {
	config := ReporterConfig{
		OutputFile:   "test.json",
		OutputFormat: "json",
		LogLevel:     "info",
	}

	reporter, err := NewReporter(config)
	if err != nil {
		t.Fatalf("Failed to create reporter: %v", err)
	}

	// Add test data
	reporter.AddResult(fuzzer.FuzzResult{
		Endpoint:     "/api/users",
		Method:       "GET",
		StatusCode:   200,
		ResponseTime: 100 * time.Millisecond,
		Timestamp:    time.Now(),
	})

	reporter.AddResult(fuzzer.FuzzResult{
		Endpoint:      "/api/users",
		Method:        "POST",
		StatusCode:    500,
		ResponseTime:  500 * time.Millisecond,
		Anomaly:       true,
		AnomalyReason: "Server error",
		Timestamp:     time.Now(),
	})

	reporter.AddResult(fuzzer.FuzzResult{
		Endpoint:     "/api/posts",
		Method:       "GET",
		StatusCode:   404,
		ResponseTime: 50 * time.Millisecond,
		Timestamp:    time.Now(),
	})

	// Generate report
	startTime := time.Now().Add(-1 * time.Minute)
	endTime := time.Now()
	targetURL := "https://api.example.com"

	report, err := reporter.GenerateReport(targetURL, startTime, endTime)
	if err != nil {
		t.Fatalf("GenerateReport() error: %v", err)
	}

	// Verify report structure
	if report.Summary.TargetURL != targetURL {
		t.Errorf("Report TargetURL = %v, want %v", report.Summary.TargetURL, targetURL)
	}

	if report.Summary.TotalRequests != 3 {
		t.Errorf("Total requests = %v, want 3", report.Summary.TotalRequests)
	}

	if report.Summary.TotalAnomalies != 1 {
		t.Errorf("Total anomalies = %v, want 1", report.Summary.TotalAnomalies)
	}

	// Endpoints are keyed by "METHOD /path", so we have:
	// "GET /api/users", "POST /api/users", "GET /api/posts"
	if len(report.Endpoints) != 3 {
		t.Errorf("Endpoint summary count = %v, want 3", len(report.Endpoints))
	}

	// Verify statistics - check status code distribution
	totalFromStats := 0
	for _, count := range report.Statistics.StatusCodeDist {
		totalFromStats += count
	}
	if totalFromStats != 3 {
		t.Errorf("Statistics total requests = %v, want 3", totalFromStats)
	}

	// Check for successful status codes (200-299)
	successfulRequests := 0
	for code, count := range report.Statistics.StatusCodeDist {
		if code >= 200 && code < 300 {
			successfulRequests += count
		}
	}
	if successfulRequests != 1 {
		t.Errorf("Successful requests = %v, want 1", successfulRequests)
	}

	// Check for failed status codes (>= 500)
	failedRequests := 0
	for code, count := range report.Statistics.StatusCodeDist {
		if code >= 500 {
			failedRequests += count
		}
	}
	if failedRequests != 1 {
		t.Errorf("Failed requests = %v, want 1", failedRequests)
	}

	// Verify findings
	if len(report.Findings) != 1 {
		t.Errorf("Findings count = %v, want 1", len(report.Findings))
	}
}

func TestReporter_PrintSummary(t *testing.T) {
	config := ReporterConfig{
		OutputFile:   "test.json",
		OutputFormat: "json",
		LogLevel:     "info",
	}

	reporter, err := NewReporter(config)
	if err != nil {
		t.Fatalf("Failed to create reporter: %v", err)
	}

	// Add test data
	reporter.AddResult(fuzzer.FuzzResult{
		Endpoint:     "/api/users",
		Method:       "GET",
		StatusCode:   200,
		ResponseTime: 100 * time.Millisecond,
	})

	reporter.AddResult(fuzzer.FuzzResult{
		Endpoint:      "/api/posts",
		Method:        "POST",
		StatusCode:    500,
		ResponseTime:  200 * time.Millisecond,
		Anomaly:       true,
		AnomalyReason: "Server error",
	})

	// Generate report first
	report, _ := reporter.GenerateReport("https://api.example.com", time.Now(), time.Now())
	reporter.SaveReport(report)

	// Capture output
	var buf bytes.Buffer
	reporter.PrintSummary(&buf)

	output := buf.String()

	// Verify output contains expected information
	expectedStrings := []string{
		"=== Fuzzing Summary ===",
		"Total Requests:",
		"Anomalies Found:",
		"Success Rate:",
		"Report saved to:",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("Output missing expected string: %q", expected)
		}
	}
}

func TestReporter_SaveReport_JSON(t *testing.T) {
	// Create temp file for testing
	tmpFile := t.TempDir() + "/test_report.json"

	config := ReporterConfig{
		OutputFile:   tmpFile,
		OutputFormat: "json",
		LogLevel:     "info",
	}

	reporter, err := NewReporter(config)
	if err != nil {
		t.Fatalf("Failed to create reporter: %v", err)
	}

	// Create a report
	report := &Report{
		Summary: Summary{
			TargetURL:      "https://api.example.com",
			TotalRequests:  100,
			TotalAnomalies: 5,
			Duration:       1 * time.Hour,
		},
		Statistics: Statistics{
			AverageResponseTime: 150 * time.Millisecond,
			StatusCodeDist:      map[int]int{200: 95, 500: 5},
			ErrorRate:           0.05,
			AnomalyRate:         0.05,
		},
	}

	// Save report
	err = reporter.SaveReport(report)
	if err != nil {
		t.Fatalf("SaveReport() error: %v", err)
	}

	// Read and verify the saved file
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read saved report: %v", err)
	}

	var savedReport Report
	err = json.Unmarshal(data, &savedReport)
	if err != nil {
		t.Fatalf("Failed to unmarshal saved report: %v", err)
	}

	if savedReport.Summary.TargetURL != report.Summary.TargetURL {
		t.Errorf("Saved TargetURL = %v, want %v", savedReport.Summary.TargetURL, report.Summary.TargetURL)
	}

	if savedReport.Summary.TotalRequests != report.Summary.TotalRequests {
		t.Errorf("Saved TotalRequests = %v, want %v",
			savedReport.Summary.TotalRequests, report.Summary.TotalRequests)
	}
}

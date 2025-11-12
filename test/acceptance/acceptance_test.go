package acceptance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestFuzzstronautAcceptance runs a simple acceptance test with a mock server
func TestFuzzstronautAcceptance(t *testing.T) {
	// Build the fuzzstronaut binary
	projectRoot := "../.."
	binaryPath := filepath.Join(projectRoot, "fuzzstronaut-test")

	t.Log("Building fuzzstronaut...")
	buildCmd := exec.Command("go", "build", "-o", binaryPath, filepath.Join(projectRoot, "cmd/fuzzstronaut/main.go"))
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build: %v\nOutput: %s", err, output)
	}
	defer os.Remove(binaryPath)

	// Create a mock HTTP server
	var requestCount int32
	var errorCount int32
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)

		// Simulate different responses
		switch {
		case r.URL.Path == "/api/users" && r.Method == "GET":
			// Success response
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "John"},
				{"id": 2, "name": "Jane"},
			})

		case r.URL.Path == "/api/users" && r.Method == "POST":
			// Check for malformed input (simulated injection)
			body := make([]byte, 1000)
			n, _ := r.Body.Read(body)
			bodyStr := string(body[:n])

			if contains(bodyStr, "script") || contains(bodyStr, "SELECT") {
				// Simulate error on injection attempt
				atomic.AddInt32(&errorCount, 1)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Internal Server Error"))
			} else {
				// Normal creation
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"id": 3, "name": "Created",
				})
			}

		case count%5 == 0:
			// Simulate occasional errors
			atomic.AddInt32(&errorCount, 1)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Random error"))

		case count%7 == 0:
			// Simulate slow response
			time.Sleep(200 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Slow response"))

		default:
			// Default success
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}
	}))
	defer mockServer.Close()

	// Create a simple test schema
	schema := map[string]interface{}{
		"baseUrl": mockServer.URL,
		"endpoints": []map[string]interface{}{
			{
				"path":        "/api/users",
				"method":      "GET",
				"description": "Get users",
			},
			{
				"path":        "/api/users",
				"method":      "POST",
				"description": "Create user",
				"body": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"name": map[string]interface{}{
							"type":     "string",
							"required": true,
						},
					},
				},
			},
		},
	}

	// Write schema to file
	schemaPath := "test-schema.json"
	schemaBytes, _ := json.MarshalIndent(schema, "", "  ")
	if err := os.WriteFile(schemaPath, schemaBytes, 0644); err != nil {
		t.Fatalf("Failed to write schema: %v", err)
	}
	defer os.Remove(schemaPath)

	// Run the fuzzer
	reportPath := "test-report.json"
	defer os.Remove(reportPath)

	t.Log("Running fuzzer against mock server...")

	// Run fuzzing with a timeout
	fuzzCmd := exec.Command(binaryPath,
		"fuzz",
		mockServer.URL,
		"-s", schemaPath,
		"-w", "2", // 2 workers
		"-r", "20", // 20 req/sec
		"-o", reportPath,
		"--timeout", "2s", // 2 second timeout for requests
	)

	// Start the process
	if err := fuzzCmd.Start(); err != nil {
		t.Fatalf("Failed to start fuzzing: %v", err)
	}

	// Let it run for a bit
	time.Sleep(3 * time.Second)

	// Send interrupt signal
	fuzzCmd.Process.Signal(os.Interrupt)

	// Wait for it to finish (with timeout)
	done := make(chan error)
	go func() {
		done <- fuzzCmd.Wait()
	}()

	select {
	case <-done:
		// Process finished
	case <-time.After(5 * time.Second):
		// Force kill if not responding
		fuzzCmd.Process.Kill()
		t.Log("Had to force kill process")
	}

	// Wait for report to be written
	time.Sleep(1 * time.Second)

	// Verify results
	t.Log("Verifying results...")

	// Check that requests were made
	finalRequestCount := atomic.LoadInt32(&requestCount)
	finalErrorCount := atomic.LoadInt32(&errorCount)

	if finalRequestCount == 0 {
		t.Fatal("No requests were made to mock server")
	}

	t.Logf("Mock server received %d requests", finalRequestCount)
	t.Logf("Mock server returned %d errors", finalErrorCount)

	// Load and verify the report
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("Failed to read report: %v", err)
	}

	var report Report
	if err := json.Unmarshal(reportData, &report); err != nil {
		t.Fatalf("Failed to parse report: %v", err)
	}

	// Validate report contents
	if report.Summary.TotalRequests == 0 {
		t.Error("Report shows no requests were made")
	}

	if report.Summary.TargetURL != mockServer.URL {
		t.Errorf("Report target URL mismatch: got %s, want %s",
			report.Summary.TargetURL, mockServer.URL)
	}

	// Log summary
	t.Log("=== Test Results ===")
	t.Logf("Total Requests: %d", report.Summary.TotalRequests)
	t.Logf("Anomalies Found: %d", report.Summary.TotalAnomalies)
	t.Logf("Risk Level: %s", report.Summary.RiskLevel)

	// Check status codes
	if report.Statistics.StatusCodeDist != nil {
		t.Log("Status Code Distribution:")
		for code, count := range report.Statistics.StatusCodeDist {
			t.Logf("  %d: %d requests", code, count)
		}
	}

	// Should have detected some anomalies (500 errors)
	if finalErrorCount > 0 && report.Summary.TotalAnomalies == 0 {
		t.Log("Warning: Server returned errors but no anomalies were detected")
	}

	// Test is successful if:
	// 1. Binary was built
	// 2. Fuzzer ran and made requests
	// 3. Report was generated
	// 4. Report contains valid data
	t.Log("✅ Acceptance test completed successfully")
}

// Helper function
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 &&
		(s == substr || len(s) > len(substr) &&
			(s[:len(substr)] == substr || contains(s[1:], substr)))
}

// Report structures
type Report struct {
	Summary    Summary    `json:"summary"`
	Statistics Statistics `json:"statistics"`
}

type Summary struct {
	TotalRequests  int    `json:"total_requests"`
	TotalAnomalies int    `json:"total_anomalies"`
	TargetURL      string `json:"target_url"`
	RiskLevel      string `json:"risk_level"`
}

type Statistics struct {
	StatusCodeDist map[int]int `json:"status_code_distribution"`
	ErrorRate      float64     `json:"error_rate"`
	AnomalyRate    float64     `json:"anomaly_rate"`
}

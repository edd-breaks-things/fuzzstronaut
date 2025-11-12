package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/edd-breaks-things/fuzzstronaut/internal/analyzer"
	"github.com/edd-breaks-things/fuzzstronaut/internal/fuzzer"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Reporter struct {
	logger  *zap.Logger
	results []fuzzer.FuzzResult
	config  ReporterConfig
}

type ReporterConfig struct {
	OutputFile   string
	OutputFormat string // json, html, markdown
	Verbose      bool
	LogLevel     string
}

type Report struct {
	Summary    Summary                       `json:"summary"`
	Findings   []Finding                     `json:"findings"`
	Statistics Statistics                    `json:"statistics"`
	Timeline   []TimelineEntry               `json:"timeline"`
	Endpoints  map[string]EndpointStatistics `json:"endpoints"`
	Timestamp  time.Time                     `json:"timestamp"`
}

type Summary struct {
	TotalRequests    int           `json:"total_requests"`
	TotalAnomalies   int           `json:"total_anomalies"`
	Duration         time.Duration `json:"duration"`
	TargetURL        string        `json:"target_url"`
	RiskLevel        string        `json:"risk_level"`
	CriticalFindings int           `json:"critical_findings"`
	HighFindings     int           `json:"high_findings"`
	MediumFindings   int           `json:"medium_findings"`
	LowFindings      int           `json:"low_findings"`
}

type Finding struct {
	Endpoint     string             `json:"endpoint"`
	Method       string             `json:"method"`
	Severity     string             `json:"severity"`
	Type         string             `json:"type"`
	Description  string             `json:"description"`
	Evidence     string             `json:"evidence,omitempty"`
	Payload      interface{}        `json:"payload,omitempty"`
	StatusCode   int                `json:"status_code"`
	ResponseTime time.Duration      `json:"response_time"`
	Timestamp    time.Time          `json:"timestamp"`
	Anomalies    []analyzer.Anomaly `json:"anomalies,omitempty"`
}

type Statistics struct {
	AverageResponseTime time.Duration `json:"average_response_time"`
	MaxResponseTime     time.Duration `json:"max_response_time"`
	MinResponseTime     time.Duration `json:"min_response_time"`
	StatusCodeDist      map[int]int   `json:"status_code_distribution"`
	ErrorRate           float64       `json:"error_rate"`
	AnomalyRate         float64       `json:"anomaly_rate"`
}

type TimelineEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	Event       string    `json:"event"`
	Description string    `json:"description"`
}

type EndpointStatistics struct {
	TotalRequests  int                `json:"total_requests"`
	TotalAnomalies int                `json:"total_anomalies"`
	StatusCodes    map[int]int        `json:"status_codes"`
	AverageTime    time.Duration      `json:"average_time"`
	Anomalies      []analyzer.Anomaly `json:"anomalies,omitempty"`
}

func NewReporter(config ReporterConfig) (*Reporter, error) {
	logger, err := createLogger(config.LogLevel, config.Verbose)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	return &Reporter{
		logger:  logger,
		results: []fuzzer.FuzzResult{},
		config:  config,
	}, nil
}

func createLogger(logLevel string, verbose bool) (*zap.Logger, error) {
	level := zapcore.InfoLevel
	switch strings.ToLower(logLevel) {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn", "warning":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	}

	config := zap.Config{
		Level:       zap.NewAtomicLevelAt(level),
		Development: verbose,
		Encoding:    "console",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "timestamp",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			FunctionKey:    zapcore.OmitKey,
			MessageKey:     "message",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.CapitalColorLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	return config.Build()
}

func (r *Reporter) AddResult(result fuzzer.FuzzResult) {
	r.results = append(r.results, result)

	if result.Anomaly {
		r.logger.Warn("Anomaly detected",
			zap.String("endpoint", result.Endpoint),
			zap.String("method", result.Method),
			zap.Int("status", result.StatusCode),
			zap.String("reason", result.AnomalyReason),
		)
	} else if r.config.Verbose {
		r.logger.Info("Request completed",
			zap.String("endpoint", result.Endpoint),
			zap.String("method", result.Method),
			zap.Int("status", result.StatusCode),
			zap.Duration("response_time", result.ResponseTime),
		)
	}
}

func (r *Reporter) GenerateReport(targetURL string, startTime, endTime time.Time) (*Report, error) {
	report := &Report{
		Summary:    r.generateSummary(targetURL, startTime, endTime),
		Findings:   r.generateFindings(),
		Statistics: r.generateStatistics(),
		Timeline:   r.generateTimeline(),
		Endpoints:  r.generateEndpointStats(),
		Timestamp:  time.Now(),
	}

	report.Summary.RiskLevel = r.calculateRiskLevel(report)

	return report, nil
}

func (r *Reporter) generateSummary(targetURL string, startTime, endTime time.Time) Summary {
	summary := Summary{
		TotalRequests:  len(r.results),
		TotalAnomalies: 0,
		Duration:       endTime.Sub(startTime),
		TargetURL:      targetURL,
	}

	severityCount := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	for _, result := range r.results {
		if result.Anomaly {
			summary.TotalAnomalies++
		}
	}

	summary.CriticalFindings = severityCount["CRITICAL"]
	summary.HighFindings = severityCount["HIGH"]
	summary.MediumFindings = severityCount["MEDIUM"]
	summary.LowFindings = severityCount["LOW"]

	return summary
}

func (r *Reporter) generateFindings() []Finding {
	findings := []Finding{}

	for _, result := range r.results {
		if result.Anomaly {
			finding := Finding{
				Endpoint:     result.Endpoint,
				Method:       result.Method,
				Description:  result.AnomalyReason,
				Payload:      result.Payload,
				StatusCode:   result.StatusCode,
				ResponseTime: result.ResponseTime,
				Timestamp:    result.Timestamp,
			}

			findings = append(findings, finding)
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		severityOrder := map[string]int{
			"CRITICAL": 0,
			"HIGH":     1,
			"MEDIUM":   2,
			"LOW":      3,
		}
		return severityOrder[findings[i].Severity] < severityOrder[findings[j].Severity]
	})

	return findings
}

func (r *Reporter) generateStatistics() Statistics {
	stats := Statistics{
		StatusCodeDist: make(map[int]int),
	}

	if len(r.results) == 0 {
		return stats
	}

	var totalTime time.Duration
	stats.MaxResponseTime = r.results[0].ResponseTime
	stats.MinResponseTime = r.results[0].ResponseTime

	errorCount := 0
	anomalyCount := 0

	for _, result := range r.results {
		totalTime += result.ResponseTime

		if result.ResponseTime > stats.MaxResponseTime {
			stats.MaxResponseTime = result.ResponseTime
		}
		if result.ResponseTime < stats.MinResponseTime {
			stats.MinResponseTime = result.ResponseTime
		}

		stats.StatusCodeDist[result.StatusCode]++

		if result.Error != nil || result.StatusCode >= 400 {
			errorCount++
		}

		if result.Anomaly {
			anomalyCount++
		}
	}

	stats.AverageResponseTime = totalTime / time.Duration(len(r.results))
	stats.ErrorRate = float64(errorCount) / float64(len(r.results))
	stats.AnomalyRate = float64(anomalyCount) / float64(len(r.results))

	return stats
}

func (r *Reporter) generateTimeline() []TimelineEntry {
	timeline := []TimelineEntry{}

	for _, result := range r.results {
		if result.Anomaly {
			timeline = append(timeline, TimelineEntry{
				Timestamp:   result.Timestamp,
				Event:       "Anomaly Detected",
				Description: fmt.Sprintf("%s %s: %s", result.Method, result.Endpoint, result.AnomalyReason),
			})
		}
	}

	return timeline
}

func (r *Reporter) generateEndpointStats() map[string]EndpointStatistics {
	endpoints := make(map[string]EndpointStatistics)

	for _, result := range r.results {
		key := fmt.Sprintf("%s %s", result.Method, result.Endpoint)

		stats, exists := endpoints[key]
		if !exists {
			stats = EndpointStatistics{
				StatusCodes: make(map[int]int),
			}
		}

		stats.TotalRequests++
		if result.Anomaly {
			stats.TotalAnomalies++
		}
		stats.StatusCodes[result.StatusCode]++
		stats.AverageTime = (stats.AverageTime + result.ResponseTime) / 2

		endpoints[key] = stats
	}

	return endpoints
}

func (r *Reporter) calculateRiskLevel(report *Report) string {
	if report.Summary.CriticalFindings > 0 {
		return "CRITICAL"
	}
	if report.Summary.HighFindings > 0 {
		return "HIGH"
	}
	if report.Summary.MediumFindings > 0 {
		return "MEDIUM"
	}
	if report.Summary.LowFindings > 0 {
		return "LOW"
	}
	return "NONE"
}

func (r *Reporter) SaveReport(report *Report) error {
	switch strings.ToLower(r.config.OutputFormat) {
	case "json":
		return r.saveJSONReport(report)
	case "html":
		return r.saveHTMLReport(report)
	case "markdown", "md":
		return r.saveMarkdownReport(report)
	default:
		return r.saveJSONReport(report)
	}
}

func (r *Reporter) saveJSONReport(report *Report) error {
	file, err := os.Create(r.config.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func (r *Reporter) saveHTMLReport(report *Report) error {
	// Simplified HTML report
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<title>Fuzzstronaut Report</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 20px; }
		.header { background: #2c3e50; color: white; padding: 20px; }
		.summary { background: #ecf0f1; padding: 15px; margin: 20px 0; }
		.findings { margin: 20px 0; }
		.finding { border-left: 4px solid #e74c3c; padding: 10px; margin: 10px 0; background: #fff5f5; }
		.stats { display: flex; gap: 20px; }
		.stat-box { flex: 1; background: #f8f9fa; padding: 10px; }
	</style>
</head>
<body>
	<div class="header">
		<h1>Fuzzstronaut Security Report</h1>
		<p>Target: %s | Date: %s</p>
	</div>
	<div class="summary">
		<h2>Summary</h2>
		<div class="stats">
			<div class="stat-box">
				<h3>%d</h3>
				<p>Total Requests</p>
			</div>
			<div class="stat-box">
				<h3>%d</h3>
				<p>Anomalies Found</p>
			</div>
			<div class="stat-box">
				<h3>%s</h3>
				<p>Risk Level</p>
			</div>
		</div>
	</div>
	<div class="findings">
		<h2>Findings</h2>
		%s
	</div>
</body>
</html>`,
		report.Summary.TargetURL,
		report.Timestamp.Format(time.RFC3339),
		report.Summary.TotalRequests,
		report.Summary.TotalAnomalies,
		report.Summary.RiskLevel,
		r.generateHTMLFindings(report.Findings))

	return os.WriteFile(r.config.OutputFile, []byte(html), 0644)
}

func (r *Reporter) generateHTMLFindings(findings []Finding) string {
	if len(findings) == 0 {
		return "<p>No security findings detected.</p>"
	}

	var html strings.Builder
	for _, finding := range findings {
		html.WriteString(fmt.Sprintf(`<div class="finding">
			<h3>%s %s</h3>
			<p><strong>Severity:</strong> %s</p>
			<p><strong>Description:</strong> %s</p>
		</div>`, finding.Method, finding.Endpoint, finding.Severity, finding.Description))
	}

	return html.String()
}

func (r *Reporter) saveMarkdownReport(report *Report) error {
	var md strings.Builder

	md.WriteString("# Fuzzstronaut Security Report\n\n")
	md.WriteString(fmt.Sprintf("**Target:** %s  \n", report.Summary.TargetURL))
	md.WriteString(fmt.Sprintf("**Date:** %s  \n\n", report.Timestamp.Format(time.RFC3339)))

	md.WriteString("## Summary\n\n")
	md.WriteString(fmt.Sprintf("- **Total Requests:** %d\n", report.Summary.TotalRequests))
	md.WriteString(fmt.Sprintf("- **Anomalies Found:** %d\n", report.Summary.TotalAnomalies))
	md.WriteString(fmt.Sprintf("- **Risk Level:** %s\n", report.Summary.RiskLevel))
	md.WriteString(fmt.Sprintf("- **Test Duration:** %v\n\n", report.Summary.Duration))

	md.WriteString("## Findings\n\n")
	if len(report.Findings) == 0 {
		md.WriteString("No security findings detected.\n\n")
	} else {
		for _, finding := range report.Findings {
			md.WriteString(fmt.Sprintf("### %s %s\n", finding.Method, finding.Endpoint))
			md.WriteString(fmt.Sprintf("- **Severity:** %s\n", finding.Severity))
			md.WriteString(fmt.Sprintf("- **Description:** %s\n", finding.Description))
			md.WriteString(fmt.Sprintf("- **Status Code:** %d\n", finding.StatusCode))
			md.WriteString(fmt.Sprintf("- **Response Time:** %v\n\n", finding.ResponseTime))
		}
	}

	md.WriteString("## Statistics\n\n")
	md.WriteString(fmt.Sprintf("- **Average Response Time:** %v\n", report.Statistics.AverageResponseTime))
	md.WriteString(fmt.Sprintf("- **Error Rate:** %.2f%%\n", report.Statistics.ErrorRate*100))
	md.WriteString(fmt.Sprintf("- **Anomaly Rate:** %.2f%%\n", report.Statistics.AnomalyRate*100))

	return os.WriteFile(r.config.OutputFile, []byte(md.String()), 0644)
}

func (r *Reporter) PrintSummary(w io.Writer) {
	if len(r.results) == 0 {
		fmt.Fprintln(w, "No results to report.")
		return
	}

	anomalies := 0
	for _, result := range r.results {
		if result.Anomaly {
			anomalies++
		}
	}

	fmt.Fprintf(w, "\n=== Fuzzing Summary ===\n")
	fmt.Fprintf(w, "Total Requests: %d\n", len(r.results))
	fmt.Fprintf(w, "Anomalies Found: %d\n", anomalies)
	fmt.Fprintf(w, "Success Rate: %.2f%%\n", (1-float64(anomalies)/float64(len(r.results)))*100)
	fmt.Fprintf(w, "Report saved to: %s\n", r.config.OutputFile)
}

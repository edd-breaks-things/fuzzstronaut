package analyzer

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type AnomalyType string

const (
	ServerError       AnomalyType = "server_error"
	ErrorDisclosure   AnomalyType = "error_disclosure"
	SQLInjection      AnomalyType = "sql_injection"
	XSSVulnerability  AnomalyType = "xss"
	PathTraversal     AnomalyType = "path_traversal"
	CommandInjection  AnomalyType = "command_injection"
	SlowResponse      AnomalyType = "slow_response"
	LargeResponse     AnomalyType = "large_response"
	EmptyResponse     AnomalyType = "empty_response"
	UnexpectedStatus  AnomalyType = "unexpected_status"
	SecurityHeader    AnomalyType = "security_header"
	RateLimitBypassed AnomalyType = "rate_limit_bypassed"
)

type Anomaly struct {
	Type        AnomalyType
	Severity    string
	Description string
	Evidence    string
	Confidence  float64
}

type DetectionResult struct {
	IsAnomaly    bool
	Anomalies    []Anomaly
	RiskScore    float64
	StatusCode   int
	ResponseTime time.Duration
	ResponseSize int
}

type Detector struct {
	patterns map[AnomalyType][]*regexp.Regexp
	baseline *ResponseBaseline
	config   DetectorConfig
}

type DetectorConfig struct {
	SlowResponseThreshold time.Duration
	LargeResponseSize     int
}

type ResponseBaseline struct {
	AverageResponseTime time.Duration
	AverageSize         int
	CommonStatusCodes   map[int]int
	NormalPatterns      []string
}

func NewDetector(config DetectorConfig) *Detector {
	if config.SlowResponseThreshold == 0 {
		config.SlowResponseThreshold = 5 * time.Second
	}
	if config.LargeResponseSize == 0 {
		config.LargeResponseSize = 1024 * 1024 // 1MB
	}

	return &Detector{
		patterns: initializePatterns(),
		config:   config,
		baseline: &ResponseBaseline{
			CommonStatusCodes: make(map[int]int),
		},
	}
}

func initializePatterns() map[AnomalyType][]*regexp.Regexp {
	patterns := make(map[AnomalyType][]*regexp.Regexp)

	patterns[ErrorDisclosure] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)stack\s*trace`),
		regexp.MustCompile(`(?i)exception.*at\s+\w+`),
		regexp.MustCompile(`(?i)error\s+in\s+.*line\s+\d+`),
		regexp.MustCompile(`(?i)fatal\s+error`),
		regexp.MustCompile(`(?i)uncaught\s+exception`),
		regexp.MustCompile(`(?i)syntax\s+error`),
		regexp.MustCompile(`(?i)undefined\s+index`),
		regexp.MustCompile(`(?i)null\s+pointer`),
		regexp.MustCompile(`(?i)debug.*=.*true`),
		regexp.MustCompile(`(?i)warning:.*in\s+.*on\s+line`),
	}

	patterns[SQLInjection] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)you\s+have\s+an\s+error\s+in\s+your\s+sql\s+syntax`),
		regexp.MustCompile(`(?i)mysql.*error`),
		regexp.MustCompile(`(?i)ora-\d{5}`),
		regexp.MustCompile(`(?i)postgresql.*error`),
		regexp.MustCompile(`(?i)sqlite.*error`),
		regexp.MustCompile(`(?i)sql\s+syntax.*incorrect`),
		regexp.MustCompile(`(?i)unknown\s+column`),
		regexp.MustCompile(`(?i)no\s+such\s+table`),
		regexp.MustCompile(`(?i)duplicate\s+entry`),
		regexp.MustCompile(`(?i)data\s+truncated`),
	}

	patterns[XSSVulnerability] = []*regexp.Regexp{
		regexp.MustCompile(`<script[^>]*>.*alert\s*\(`),
		regexp.MustCompile(`javascript:\s*alert`),
		regexp.MustCompile(`on\w+\s*=\s*["'].*alert`),
		regexp.MustCompile(`<iframe[^>]*src=["']javascript:`),
		regexp.MustCompile(`document\.cookie`),
		regexp.MustCompile(`<svg[^>]*onload\s*=`),
	}

	patterns[PathTraversal] = []*regexp.Regexp{
		regexp.MustCompile(`root:.*:0:0`),
		regexp.MustCompile(`\[boot\s+loader\]`),
		regexp.MustCompile(`/etc/passwd`),
		regexp.MustCompile(`C:\\Windows\\system32`),
		regexp.MustCompile(`Program\s+Files`),
	}

	patterns[CommandInjection] = []*regexp.Regexp{
		regexp.MustCompile(`uid=\d+\(.+\)\s+gid=`),
		regexp.MustCompile(`Linux\s+\w+\s+\d+\.\d+`),
		regexp.MustCompile(`Microsoft\s+Windows`),
		regexp.MustCompile(`total\s+\d+\s+drwx`),
		regexp.MustCompile(`\d+\s+bytes\s+from\s+\d+\.\d+\.\d+\.\d+`),
	}

	return patterns
}

func (d *Detector) Analyze(statusCode int, headers map[string][]string, body []byte, responseTime time.Duration) DetectionResult {
	result := DetectionResult{
		StatusCode:   statusCode,
		ResponseTime: responseTime,
		ResponseSize: len(body),
		Anomalies:    []Anomaly{},
	}

	bodyStr := string(body)

	if statusCode >= 500 {
		result.Anomalies = append(result.Anomalies, Anomaly{
			Type:        ServerError,
			Severity:    "HIGH",
			Description: fmt.Sprintf("Server error status code: %d", statusCode),
			Confidence:  1.0,
		})
	}

	if responseTime > d.config.SlowResponseThreshold {
		result.Anomalies = append(result.Anomalies, Anomaly{
			Type:        SlowResponse,
			Severity:    "MEDIUM",
			Description: fmt.Sprintf("Response time exceeds threshold: %v", responseTime),
			Confidence:  0.8,
		})
	}

	if len(body) > d.config.LargeResponseSize {
		result.Anomalies = append(result.Anomalies, Anomaly{
			Type:        LargeResponse,
			Severity:    "LOW",
			Description: fmt.Sprintf("Response size exceeds threshold: %d bytes", len(body)),
			Confidence:  0.6,
		})
	}

	if len(body) == 0 && statusCode == 200 {
		result.Anomalies = append(result.Anomalies, Anomaly{
			Type:        EmptyResponse,
			Severity:    "MEDIUM",
			Description: "Empty response body with 200 status",
			Confidence:  0.7,
		})
	}

	for anomalyType, patterns := range d.patterns {
		for _, pattern := range patterns {
			if matches := pattern.FindAllString(bodyStr, -1); len(matches) > 0 {
				result.Anomalies = append(result.Anomalies, Anomaly{
					Type:        anomalyType,
					Severity:    d.getSeverity(anomalyType),
					Description: fmt.Sprintf("Pattern matched for %s", anomalyType),
					Evidence:    truncateEvidence(matches[0], 100),
					Confidence:  d.getConfidence(anomalyType, len(matches)),
				})
				break
			}
		}
	}

	d.checkSecurityHeaders(headers, &result)

	d.checkJSONErrors(body, &result)

	result.IsAnomaly = len(result.Anomalies) > 0
	result.RiskScore = d.calculateRiskScore(result.Anomalies)

	return result
}

func (d *Detector) checkSecurityHeaders(headers map[string][]string, result *DetectionResult) {
	securityHeaders := []string{
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Strict-Transport-Security",
		"Content-Security-Policy",
	}

	missingHeaders := []string{}
	for _, header := range securityHeaders {
		if _, ok := headers[header]; !ok {
			missingHeaders = append(missingHeaders, header)
		}
	}

	if len(missingHeaders) > 0 {
		result.Anomalies = append(result.Anomalies, Anomaly{
			Type:        SecurityHeader,
			Severity:    "LOW",
			Description: fmt.Sprintf("Missing security headers: %s", strings.Join(missingHeaders, ", ")),
			Confidence:  0.5,
		})
	}
}

func (d *Detector) checkJSONErrors(body []byte, result *DetectionResult) {
	var jsonData map[string]interface{}
	if err := json.Unmarshal(body, &jsonData); err == nil {
		errorFields := []string{"error", "errors", "exception", "stacktrace", "debug"}
		for _, field := range errorFields {
			if value, ok := jsonData[field]; ok {
				if value != nil && value != "" && value != false {
					result.Anomalies = append(result.Anomalies, Anomaly{
						Type:        ErrorDisclosure,
						Severity:    "MEDIUM",
						Description: fmt.Sprintf("JSON error field '%s' found", field),
						Evidence:    truncateEvidence(fmt.Sprintf("%v", value), 100),
						Confidence:  0.7,
					})
				}
			}
		}
	}
}

func (d *Detector) getSeverity(anomalyType AnomalyType) string {
	severityMap := map[AnomalyType]string{
		ServerError:       "HIGH",
		ErrorDisclosure:   "MEDIUM",
		SQLInjection:      "CRITICAL",
		XSSVulnerability:  "HIGH",
		PathTraversal:     "HIGH",
		CommandInjection:  "CRITICAL",
		SlowResponse:      "LOW",
		LargeResponse:     "LOW",
		EmptyResponse:     "MEDIUM",
		UnexpectedStatus:  "MEDIUM",
		SecurityHeader:    "LOW",
		RateLimitBypassed: "MEDIUM",
	}

	if severity, ok := severityMap[anomalyType]; ok {
		return severity
	}
	return "UNKNOWN"
}

func (d *Detector) getConfidence(anomalyType AnomalyType, matchCount int) float64 {
	baseConfidence := map[AnomalyType]float64{
		ServerError:      1.0,
		ErrorDisclosure:  0.7,
		SQLInjection:     0.9,
		XSSVulnerability: 0.8,
		PathTraversal:    0.8,
		CommandInjection: 0.9,
		SlowResponse:     0.6,
		LargeResponse:    0.5,
		EmptyResponse:    0.7,
		SecurityHeader:   0.5,
	}

	confidence := baseConfidence[anomalyType]
	if matchCount > 1 {
		confidence = min(1.0, confidence+(float64(matchCount)*0.05))
	}

	return confidence
}

func (d *Detector) calculateRiskScore(anomalies []Anomaly) float64 {
	if len(anomalies) == 0 {
		return 0.0
	}

	severityWeights := map[string]float64{
		"CRITICAL": 1.0,
		"HIGH":     0.8,
		"MEDIUM":   0.5,
		"LOW":      0.2,
		"UNKNOWN":  0.1,
	}

	totalScore := 0.0
	for _, anomaly := range anomalies {
		weight := severityWeights[anomaly.Severity]
		totalScore += weight * anomaly.Confidence
	}

	normalizedScore := min(1.0, totalScore/float64(len(anomalies)))

	return normalizedScore
}

func (d *Detector) UpdateBaseline(statusCode int, responseTime time.Duration, responseSize int) {
	if d.baseline == nil {
		d.baseline = &ResponseBaseline{
			CommonStatusCodes: make(map[int]int),
		}
	}

	d.baseline.CommonStatusCodes[statusCode]++

	d.baseline.AverageResponseTime = (d.baseline.AverageResponseTime + responseTime) / 2
	d.baseline.AverageSize = (d.baseline.AverageSize + responseSize) / 2
}

func (d *Detector) IsAnomalousBasedOnBaseline(statusCode int, responseTime time.Duration, responseSize int) bool {
	if d.baseline == nil {
		return false
	}

	if _, ok := d.baseline.CommonStatusCodes[statusCode]; !ok && len(d.baseline.CommonStatusCodes) > 0 {
		return true
	}

	if responseTime > d.baseline.AverageResponseTime*3 {
		return true
	}

	if responseSize > d.baseline.AverageSize*10 {
		return true
	}

	return false
}

func truncateEvidence(evidence string, maxLen int) string {
	if len(evidence) <= maxLen {
		return evidence
	}
	return evidence[:maxLen] + "..."
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

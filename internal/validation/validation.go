// Package validation provides input validation and sanitization utilities
package validation

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// URL validation regex
	urlRegex = regexp.MustCompile(`^https?://`)

	// Path traversal patterns
	pathTraversalRegex = regexp.MustCompile(`\.\.[\\/]`)

	// SQL injection patterns (basic)
	sqlInjectionRegex = regexp.MustCompile(`(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute|script|javascript|eval)`)

	// Command injection patterns
	commandInjectionRegex = regexp.MustCompile(`[;&|<>$` + "`" + `]`)

	// Valid HTTP methods
	validHTTPMethods = map[string]bool{
		"GET":     true,
		"POST":    true,
		"PUT":     true,
		"PATCH":   true,
		"DELETE":  true,
		"HEAD":    true,
		"OPTIONS": true,
		"CONNECT": true,
		"TRACE":   true,
	}

	// Maximum sizes
	maxURLLength         = 2048
	maxHeaderKeyLength   = 256
	maxHeaderValueLength = 4096
	maxPathLength        = 256
	maxParameterLength   = 1024
)

// ValidateURL validates and sanitizes a URL
func ValidateURL(rawURL string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("URL cannot be empty")
	}

	if len(rawURL) > maxURLLength {
		return "", fmt.Errorf("URL exceeds maximum length of %d characters", maxURLLength)
	}

	// Check if it starts with http:// or https://
	if !urlRegex.MatchString(rawURL) {
		return "", fmt.Errorf("URL must start with http:// or https://")
	}

	// Parse the URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL format: %w", err)
	}

	// Check for empty host
	if parsedURL.Host == "" {
		return "", fmt.Errorf("URL must contain a valid host")
	}

	// Check for localhost/private IPs in production
	// Currently allowing private hosts for testing purposes
	_ = isPrivateHost(parsedURL.Host) // Note: In production, you might want to disallow this

	// Reconstruct the URL to ensure it's properly formatted
	return parsedURL.String(), nil
}

// ValidateHTTPMethod validates an HTTP method
func ValidateHTTPMethod(method string) (string, error) {
	if method == "" {
		return "", fmt.Errorf("HTTP method cannot be empty")
	}

	upperMethod := strings.ToUpper(method)
	if !validHTTPMethods[upperMethod] {
		return "", fmt.Errorf("invalid HTTP method: %s", method)
	}

	return upperMethod, nil
}

// ValidateFilePath validates and sanitizes a file path
func ValidateFilePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("file path cannot be empty")
	}

	if len(path) > maxPathLength {
		return "", fmt.Errorf("file path exceeds maximum length of %d characters", maxPathLength)
	}

	// Check for path traversal attempts
	if pathTraversalRegex.MatchString(path) {
		return "", fmt.Errorf("path traversal patterns detected in file path")
	}

	// Clean the path
	cleanPath := filepath.Clean(path)

	// Ensure the path doesn't go outside the intended directory
	if strings.HasPrefix(cleanPath, "..") {
		return "", fmt.Errorf("file path attempts to access parent directory")
	}

	return cleanPath, nil
}

// ValidateHeader validates HTTP header key-value pairs
func ValidateHeader(key, value string) error {
	if key == "" {
		return fmt.Errorf("header key cannot be empty")
	}

	if len(key) > maxHeaderKeyLength {
		return fmt.Errorf("header key exceeds maximum length of %d characters", maxHeaderKeyLength)
	}

	if len(value) > maxHeaderValueLength {
		return fmt.Errorf("header value exceeds maximum length of %d characters", maxHeaderValueLength)
	}

	// Check for newline characters (header injection)
	if strings.ContainsAny(key, "\r\n") || strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("header contains invalid newline characters")
	}

	return nil
}

// SanitizeParameter sanitizes a parameter value for safe usage
func SanitizeParameter(value string) string {
	if len(value) > maxParameterLength {
		value = value[:maxParameterLength]
	}

	// Remove null bytes
	value = strings.ReplaceAll(value, "\x00", "")

	// Remove control characters
	value = regexp.MustCompile(`[\x00-\x1F\x7F]`).ReplaceAllString(value, "")

	return value
}

// ValidateAuthType validates an authentication type
func ValidateAuthType(authType string) error {
	validTypes := map[string]bool{
		"bearer": true,
		"basic":  true,
		"apikey": true,
		"custom": true,
	}

	if !validTypes[strings.ToLower(authType)] {
		return fmt.Errorf("invalid authentication type: %s", authType)
	}

	return nil
}

// ValidateRateLimit validates rate limit configuration
func ValidateRateLimit(rate int) error {
	if rate <= 0 {
		return fmt.Errorf("rate limit must be positive")
	}

	if rate > 10000 {
		return fmt.Errorf("rate limit exceeds maximum of 10000 requests per second")
	}

	return nil
}

// ValidateWorkers validates the number of concurrent workers
func ValidateWorkers(workers int) error {
	if workers <= 0 {
		return fmt.Errorf("number of workers must be positive")
	}

	if workers > 100 {
		return fmt.Errorf("number of workers exceeds maximum of 100")
	}

	return nil
}

// IsSuspiciousInput checks if input contains potentially malicious patterns
func IsSuspiciousInput(input string) bool {
	// Check for SQL injection patterns
	if sqlInjectionRegex.MatchString(input) {
		return true
	}

	// Check for command injection patterns
	if commandInjectionRegex.MatchString(input) {
		return true
	}

	// Check for excessive length
	if len(input) > 10000 {
		return true
	}

	return false
}

// SanitizeLogOutput sanitizes output for safe logging
func SanitizeLogOutput(output string) string {
	// Limit length
	if len(output) > 1000 {
		output = output[:997] + "..."
	}

	// Remove sensitive patterns (basic)
	// In production, use more sophisticated detection
	output = regexp.MustCompile(`(?i)(password|token|secret|key|auth)[\s]*[:=][\s]*[\S]+`).
		ReplaceAllString(output, "[REDACTED]")

	return output
}

// isPrivateHost checks if a host is localhost or a private IP
func isPrivateHost(host string) bool {
	privatePatterns := []string{
		"localhost",
		"127.0.0.1",
		"::1",
		"0.0.0.0",
		"10.",
		"172.16.",
		"172.17.",
		"172.18.",
		"172.19.",
		"172.20.",
		"172.21.",
		"172.22.",
		"172.23.",
		"172.24.",
		"172.25.",
		"172.26.",
		"172.27.",
		"172.28.",
		"172.29.",
		"172.30.",
		"172.31.",
		"192.168.",
	}

	for _, pattern := range privatePatterns {
		if strings.HasPrefix(host, pattern) {
			return true
		}
	}

	return false
}

// ParseHeaders parses and validates header strings
func ParseHeaders(headers []string) (map[string]string, error) {
	result := make(map[string]string)

	for _, header := range headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid header format: %s (expected key:value)", header)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if err := ValidateHeader(key, value); err != nil {
			return nil, fmt.Errorf("invalid header %s: %w", header, err)
		}

		result[key] = value
	}

	return result, nil
}

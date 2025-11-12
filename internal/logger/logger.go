// Package logger provides structured logging for the fuzzstronaut application
package logger

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	// Global logger instance
	log *zap.Logger
	// Sugar logger for more convenient logging
	sugar *zap.SugaredLogger
)

func init() {
	// Initialize with a default production logger
	var err error
	log, err = zap.NewProduction()
	if err != nil {
		panic(fmt.Sprintf("failed to initialize logger: %v", err))
	}
	sugar = log.Sugar()
}

// InitLogger initializes the logger with the specified configuration
func InitLogger(level string, verbose bool) error {
	var config zap.Config

	if verbose {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		config = zap.NewProductionConfig()
	}

	// Parse and set log level
	logLevel, err := zapcore.ParseLevel(level)
	if err != nil {
		return fmt.Errorf("invalid log level %s: %w", level, err)
	}
	config.Level = zap.NewAtomicLevelAt(logLevel)

	// Build logger
	newLogger, err := config.Build()
	if err != nil {
		return fmt.Errorf("failed to build logger: %w", err)
	}

	// Replace global logger
	if log != nil {
		_ = log.Sync()
	}
	log = newLogger
	sugar = log.Sugar()

	return nil
}

// Get returns the global logger instance
func Get() *zap.Logger {
	return log
}

// GetSugar returns the sugared logger for convenience
func GetSugar() *zap.SugaredLogger {
	return sugar
}

// Sync flushes any buffered log entries
func Sync() error {
	if log != nil {
		return log.Sync()
	}
	return nil
}

// Debug logs a debug message
func Debug(msg string, fields ...zap.Field) {
	log.Debug(msg, fields...)
}

// Info logs an info message
func Info(msg string, fields ...zap.Field) {
	log.Info(msg, fields...)
}

// Warn logs a warning message
func Warn(msg string, fields ...zap.Field) {
	log.Warn(msg, fields...)
}

// Error logs an error message
func Error(msg string, fields ...zap.Field) {
	log.Error(msg, fields...)
}

// Fatal logs a fatal message and exits the program
func Fatal(msg string, fields ...zap.Field) {
	log.Fatal(msg, fields...)
}

// With creates a child logger with additional fields
func With(fields ...zap.Field) *zap.Logger {
	return log.With(fields...)
}

// Debugf logs a formatted debug message
func Debugf(template string, args ...interface{}) {
	sugar.Debugf(template, args...)
}

// Infof logs a formatted info message
func Infof(template string, args ...interface{}) {
	sugar.Infof(template, args...)
}

// Warnf logs a formatted warning message
func Warnf(template string, args ...interface{}) {
	sugar.Warnf(template, args...)
}

// Errorf logs a formatted error message
func Errorf(template string, args ...interface{}) {
	sugar.Errorf(template, args...)
}

// Fatalf logs a formatted fatal message and exits the program
func Fatalf(template string, args ...interface{}) {
	sugar.Fatalf(template, args...)
}

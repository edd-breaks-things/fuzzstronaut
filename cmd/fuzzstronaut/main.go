package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/edd-breaks-things/fuzzstronaut/internal/auth"
	"github.com/edd-breaks-things/fuzzstronaut/internal/fuzzer"
	"github.com/edd-breaks-things/fuzzstronaut/internal/logger"
	"github.com/edd-breaks-things/fuzzstronaut/internal/reporter"
	"github.com/edd-breaks-things/fuzzstronaut/internal/schema"
	"github.com/edd-breaks-things/fuzzstronaut/internal/validation"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	verbose bool

	rootCmd = &cobra.Command{
		Use:   "fuzzstronaut",
		Short: "A blazing fast REST API fuzzer",
		Long: `Fuzzstronaut is a security testing tool that fuzzes REST API endpoints
to discover unexpected behaviors, vulnerabilities, and edge cases.

It supports OpenAPI schemas, multiple authentication methods, and intelligent
mutation strategies to effectively test your APIs.`,
	}

	fuzzCmd = &cobra.Command{
		Use:   "fuzz [target-url]",
		Short: "Start fuzzing a REST API endpoint",
		Long:  `Fuzz a REST API endpoint using the provided schema and configuration`,
		Args:  cobra.ExactArgs(1),
		RunE:  runFuzz,
	}

	validateCmd = &cobra.Command{
		Use:   "validate [schema-file]",
		Short: "Validate an OpenAPI schema file",
		Args:  cobra.ExactArgs(1),
		RunE:  runValidate,
	}
)

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.fuzzstronaut.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	fuzzCmd.Flags().StringP("schema", "s", "", "OpenAPI schema file (required)")
	fuzzCmd.Flags().StringP("auth-type", "a", "", "Authentication type (bearer, basic, apikey)")
	fuzzCmd.Flags().StringP("auth-value", "t", "", "Authentication value (token, credentials, or key)")
	fuzzCmd.Flags().IntP("workers", "w", 10, "Number of concurrent workers")
	fuzzCmd.Flags().IntP("rate-limit", "r", 100, "Requests per second rate limit")
	fuzzCmd.Flags().StringP("output", "o", "fuzz-report.json", "Output report file")
	fuzzCmd.Flags().Duration("timeout", 30*time.Second, "Request timeout")
	fuzzCmd.Flags().StringSliceP("headers", "H", []string{}, "Additional headers (key:value)")
	fuzzCmd.Flags().Bool("follow-redirects", true, "Follow HTTP redirects")
	fuzzCmd.Flags().StringP("method", "m", "", "HTTP method to fuzz (GET, POST, PUT, DELETE, etc)")
	fuzzCmd.Flags().StringP("data", "d", "", "Custom data template file (JSON)")

	_ = fuzzCmd.MarkFlagRequired("schema")

	rootCmd.AddCommand(fuzzCmd)
	rootCmd.AddCommand(validateCmd)

	_ = viper.BindPFlags(fuzzCmd.Flags())
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.SetConfigName(".fuzzstronaut")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil && verbose {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func runFuzz(cmd *cobra.Command, args []string) error {
	targetURL := args[0]
	schemaFile := viper.GetString("schema")

	// Validate inputs
	validatedURL, err := validation.ValidateURL(targetURL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	targetURL = validatedURL

	validatedPath, err := validation.ValidateFilePath(schemaFile)
	if err != nil {
		return fmt.Errorf("invalid schema file path: %w", err)
	}
	schemaFile = validatedPath

	// Initialize logger
	logLevel := "info"
	if verbose {
		logLevel = "debug"
	}
	if err := logger.InitLogger(logLevel, verbose); err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer func() {
		_ = logger.Sync()
	}()

	logger.Infof("🚀 Starting fuzzing campaign against: %s", targetURL)
	logger.Infof("📋 Using schema: %s", schemaFile)

	// Parse schema
	schemaData, err := os.Open(schemaFile)
	if err != nil {
		return fmt.Errorf("failed to open schema file: %w", err)
	}
	defer func() {
		_ = schemaData.Close()
	}()

	logger.Debug("Detecting schema format")
	format, err := schema.DetectSchemaFormat(schemaData)
	if err != nil {
		logger.Errorf("Failed to detect schema format: %v", err)
		return fmt.Errorf("failed to detect schema format: %w", err)
	}
	logger.Debugf("Detected schema format: %s", format)

	// Reset file pointer
	_, _ = schemaData.Seek(0, 0)

	parser, err := schema.NewParser(format)
	if err != nil {
		return fmt.Errorf("failed to create parser: %w", err)
	}

	apiSchema, err := parser.Parse(schemaData)
	if err != nil {
		return fmt.Errorf("failed to parse schema: %w", err)
	}

	// Setup authentication
	authType := viper.GetString("auth-type")
	authValue := viper.GetString("auth-value")
	var authHeader, authHeaderValue string

	if authType != "" {
		if err := validation.ValidateAuthType(authType); err != nil {
			return fmt.Errorf("invalid auth type: %w", err)
		}
	}

	if authType != "" && authValue != "" {
		authConfig, err := auth.ParseAuthValue(auth.AuthType(authType), authValue)
		if err != nil {
			return fmt.Errorf("failed to parse auth: %w", err)
		}

		authenticator, err := auth.NewAuthenticator(authConfig)
		if err != nil {
			return fmt.Errorf("failed to create authenticator: %w", err)
		}

		headers := authenticator.GetHeaders()
		for k, v := range headers {
			authHeader = k
			authHeaderValue = v
			break
		}
	}

	// Validate and configure fuzzing engine
	workers := viper.GetInt("workers")
	if err := validation.ValidateWorkers(workers); err != nil {
		return fmt.Errorf("invalid workers configuration: %w", err)
	}

	rateLimit := viper.GetInt("rate-limit")
	if err := validation.ValidateRateLimit(rateLimit); err != nil {
		return fmt.Errorf("invalid rate limit: %w", err)
	}

	headers, err := validation.ParseHeaders(viper.GetStringSlice("headers"))
	if err != nil {
		return fmt.Errorf("invalid headers: %w", err)
	}

	config := &fuzzer.FuzzConfig{
		TargetURL:  targetURL,
		Schema:     apiSchema,
		Workers:    workers,
		RateLimit:  rateLimit,
		Timeout:    viper.GetDuration("timeout"),
		Headers:    headers,
		AuthHeader: authHeader,
		AuthValue:  authHeaderValue,
	}

	// Create reporter
	reporterConfig := reporter.ReporterConfig{
		OutputFile:   viper.GetString("output"),
		OutputFormat: "json",
		Verbose:      verbose,
		LogLevel:     "info",
	}

	rep, err := reporter.NewReporter(reporterConfig)
	if err != nil {
		return fmt.Errorf("failed to create reporter: %w", err)
	}

	// Start fuzzing
	engine := fuzzer.NewEngine(config)
	results := engine.Start()

	startTime := time.Now()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Process results with graceful shutdown
	done := make(chan bool)
	go func() {
		select {
		case <-sigChan:
			fmt.Println("\n⚠️  Received interrupt signal, gracefully shutting down...")
			engine.Stop()
			done <- true
		case <-time.After(30 * time.Second): // Run for 30 seconds max
			fmt.Println("\n⏱️  Time limit reached, stopping fuzzing...")
			engine.Stop()
			done <- false
		}
	}()

	// Collect results
	go func() {
		for result := range results {
			rep.AddResult(result)
		}
		done <- true
	}()

	// Wait for completion
	wasInterrupted := <-done
	endTime := time.Now()

	if wasInterrupted {
		fmt.Println("✅ Gracefully stopped fuzzing campaign")
	}

	// Generate report
	report, err := rep.GenerateReport(targetURL, startTime, endTime)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	if err := rep.SaveReport(report); err != nil {
		return fmt.Errorf("failed to save report: %w", err)
	}

	rep.PrintSummary(os.Stdout)

	return nil
}

func runValidate(cmd *cobra.Command, args []string) error {
	schemaFile := args[0]
	fmt.Printf("🔍 Validating schema: %s\n", schemaFile)

	schemaData, err := os.Open(schemaFile)
	if err != nil {
		return fmt.Errorf("failed to open schema file: %w", err)
	}
	defer func() {
		_ = schemaData.Close()
	}()

	logger.Debug("Detecting schema format")
	format, err := schema.DetectSchemaFormat(schemaData)
	if err != nil {
		logger.Errorf("Failed to detect schema format: %v", err)
		return fmt.Errorf("failed to detect schema format: %w", err)
	}
	logger.Debugf("Detected schema format: %s", format)

	fmt.Printf("✅ Detected format: %s\n", format)

	// Reset file pointer
	_, _ = schemaData.Seek(0, 0)

	parser, err := schema.NewParser(format)
	if err != nil {
		return fmt.Errorf("failed to create parser: %w", err)
	}

	if err := parser.ValidateSchema(schemaData); err != nil {
		return fmt.Errorf("❌ Schema validation failed: %w", err)
	}

	fmt.Println("✅ Schema is valid!")
	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

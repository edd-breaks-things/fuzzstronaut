.PHONY: build test format clean

# Build variables
BINARY_NAME=fuzzstronaut
BUILD_DIR=bin
CMD_PATH=cmd/fuzzstronaut/main.go

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_PATH)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Run all tests
test:
	@echo "Running tests..."
	@go test -v -race -cover ./...

# Format code
format:
	@echo "Formatting code..."
	@go fmt ./...
	@gofmt -s -w .

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html
	@echo "Clean complete"
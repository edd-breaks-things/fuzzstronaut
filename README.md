# 🚀 Fuzzstronaut

![Fuzzstronaut](media/image.png)

A blazing fast REST API fuzzer for security testing, written in Go with a focus on speed and simplicity.

## Features

- **🔍 Smart Fuzzing**: Intelligent mutation strategies including boundary values, SQL injection, XSS, and more
- **📋 Schema Support**: Works with OpenAPI 3.0 specs and custom JSON schemas
- **🔐 Authentication**: Support for Bearer tokens, Basic auth, API keys, and custom headers
- **⚡ Fast & Concurrent**: Parallel fuzzing with configurable workers and rate limiting
- **🎯 Anomaly Detection**: Automatic detection of security issues, error disclosures, and performance problems
- **📊 Comprehensive Reports**: JSON, HTML, and Markdown report formats

## Installation

```bash
go install github.com/edd-breaks-things/fuzzstronaut/cmd/fuzzstronaut@latest
```

Or build from source:

```bash
git clone https://github.com/edd-breaks-things/fuzzstronaut.git
cd fuzzstronaut
go build -o fuzzstronaut cmd/fuzzstronaut/main.go
```

## Quick Start - Fuzzing an API with Bearer Token

### Step 1: Create Your API Schema

Create a file `api-schema.json` with your API endpoints:

```json
{
  "baseUrl": "https://api.yourcompany.com",
  "auth": {
    "type": "bearer",
    "token": "YOUR_BEARER_TOKEN_HERE"
  },
  "endpoints": [
    {
      "path": "/api/v1/users",
      "method": "GET",
      "description": "List all users",
      "parameters": [
        {
          "name": "page",
          "in": "query",
          "type": "integer",
          "required": false
        },
        {
          "name": "limit",
          "in": "query",
          "type": "integer",
          "required": false
        }
      ]
    },
    {
      "path": "/api/v1/users/{id}",
      "method": "GET",
      "description": "Get user by ID",
      "parameters": [
        {
          "name": "id",
          "in": "path",
          "type": "string",
          "required": true
        }
      ]
    },
    {
      "path": "/api/v1/users",
      "method": "POST",
      "description": "Create a new user",
      "body": {
        "type": "object",
        "properties": {
          "name": {
            "type": "string",
            "required": true
          },
          "email": {
            "type": "string",
            "required": true
          },
          "role": {
            "type": "string",
            "enum": ["admin", "user", "viewer"],
            "required": false
          }
        }
      }
    },
    {
      "path": "/api/v1/search",
      "method": "GET",
      "description": "Search functionality",
      "parameters": [
        {
          "name": "q",
          "in": "query",
          "type": "string",
          "required": true
        },
        {
          "name": "type",
          "in": "query",
          "type": "string",
          "enum": ["users", "documents", "all"],
          "required": false
        }
      ]
    }
  ]
}
```

### Step 2: Run the Fuzzer

```bash
# Basic fuzzing with bearer token
fuzzstronaut fuzz https://api.yourcompany.com \
  -s work-api-schema.json \
  -a bearer \
  -t "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# With custom settings for a staging environment
fuzzstronaut fuzz https://staging-api.yourcompany.com \
  -s work-api-schema.json \
  -a bearer \
  -t "YOUR_STAGING_TOKEN" \
  -w 5 \
  -r 50 \
  -o staging-security-report.json \
  --timeout 10s

# With additional headers
fuzzstronaut fuzz https://api.yourcompany.com \
  -s work-api-schema.json \
  -a bearer \
  -t "YOUR_TOKEN" \
  -H "X-Tenant-ID:12345" \
  -H "X-Request-ID:fuzzing-test" \
  -o security-audit.json
```

### Step 3: Review the Report

After fuzzing completes, you'll get a detailed JSON report:

```json
{
  "summary": {
    "total_requests": 1523,
    "total_anomalies": 12,
    "target_url": "https://api.yourcompany.com",
    "duration": "2m15s",
    "risk_level": "MEDIUM"
  },
  "anomalies": [
    {
      "type": "SQL_INJECTION",
      "endpoint": "/api/v1/search",
      "method": "GET",
      "payload": {"q": "' OR '1'='1"},
      "response_code": 500,
      "details": "Server error with SQL-like input"
    },
    {
      "type": "XSS_POTENTIAL",
      "endpoint": "/api/v1/users",
      "method": "POST",
      "payload": {"name": "<script>alert(1)</script>"},
      "response_code": 200,
      "details": "Unescaped input accepted"
    }
  ]
}
```

## Alternative: Using a Config File

Create `.fuzzstronaut.yaml`:

```yaml
workers: 10
rate-limit: 100
timeout: 30
output: api-security-report.json
auth-type: bearer
auth-value: "YOUR_BEARER_TOKEN_HERE"
headers:
  - "X-Tenant-ID: production"
  - "Accept: application/json"
```

Then run:

```bash
fuzzstronaut fuzz https://api.yourcompany.com -s work-api-schema.json --config .fuzzstronaut.yaml
```

## OpenAPI Schema Support

If you have an OpenAPI/Swagger specification, you can use it directly:

```bash
# Download your OpenAPI spec
curl https://api.yourcompany.com/swagger.json -o openapi.json

# Fuzz with bearer authentication
fuzzstronaut fuzz https://api.yourcompany.com \
  -s openapi.json \
  -a bearer \
  -t "YOUR_TOKEN"
```

## What Gets Tested

Fuzzstronaut automatically tests for:

- **Injection Attacks**: SQL, NoSQL, Command injection, LDAP injection
- **XSS Vulnerabilities**: Script tags, event handlers, data URIs
- **Authentication Issues**: Missing auth, token manipulation
- **Authorization Flaws**: Path traversal, IDOR attempts
- **Input Validation**: Boundary values, type confusion, format strings
- **Error Handling**: Stack traces, debug information leakage
- **Performance Issues**: Slow queries, resource exhaustion

## Security Best Practices

⚠️ **Important Security Notes**:

1. **Only test APIs you own or have explicit permission to test**
2. **Use staging/test environments when possible**
3. **Start with low worker counts and rate limits**
4. **Monitor your API's response during testing**
5. **Never share bearer tokens in public repositories**

## Command Reference

```
fuzzstronaut fuzz [target-url]

Flags:
  -s, --schema string      API schema file (required)
  -a, --auth-type string   Authentication type (bearer, basic, apikey)
  -t, --auth-value string  Authentication value/token
  -w, --workers int        Number of concurrent workers (default 10)
  -r, --rate-limit int     Requests per second (default 100)
  -o, --output string      Output report file (default "fuzz-report.json")
  --timeout duration       Request timeout (default 30s)
  -H, --headers strings    Additional headers (key:value)
  -v, --verbose           Verbose output
  --config string         Config file
```

## License

MIT

## Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for complying with all applicable laws and obtaining proper authorization before testing any systems.
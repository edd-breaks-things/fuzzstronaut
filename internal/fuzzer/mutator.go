package fuzzer

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"time"
)

type MutationStrategy string

const (
	BoundaryValues MutationStrategy = "boundary"
	TypeConfusion  MutationStrategy = "type_confusion"
	SQLInjection   MutationStrategy = "sql_injection"
	XSSPayloads    MutationStrategy = "xss"
	CommandInject  MutationStrategy = "command_injection"
	PathTraversal  MutationStrategy = "path_traversal"
	RandomMutation MutationStrategy = "random"
	NullValues     MutationStrategy = "null"
	LongStrings    MutationStrategy = "long_strings"
	SpecialChars   MutationStrategy = "special_chars"
	FormatString   MutationStrategy = "format_string"
	XMLInjection   MutationStrategy = "xml_injection"
	JSONInjection  MutationStrategy = "json_injection"
)

type Mutator struct {
	rand       *rand.Rand
	strategies []MutationStrategy
	payloads   map[MutationStrategy][]interface{}
}

func NewMutator(strategies []MutationStrategy) *Mutator {
	if len(strategies) == 0 {
		strategies = []MutationStrategy{
			BoundaryValues,
			TypeConfusion,
			SQLInjection,
			XSSPayloads,
			CommandInject,
			PathTraversal,
			RandomMutation,
			NullValues,
			LongStrings,
			SpecialChars,
		}
	}

	return &Mutator{
		rand:       rand.New(rand.NewSource(time.Now().UnixNano())),
		strategies: strategies,
		payloads:   initializePayloads(),
	}
}

func initializePayloads() map[MutationStrategy][]interface{} {
	return map[MutationStrategy][]interface{}{
		BoundaryValues: {
			0, -1, 1,
			math.MaxInt32, math.MinInt32,
			math.MaxInt64, math.MinInt64,
			math.MaxFloat32, math.MaxFloat64,
			-math.MaxFloat32, -math.MaxFloat64,
			"", " ",
		},
		TypeConfusion: {
			"true", "false", "null", "undefined",
			"NaN", "Infinity", "-Infinity",
			[]interface{}{}, map[string]interface{}{},
			0, "0", false,
		},
		SQLInjection: {
			"' OR '1'='1",
			"1; DROP TABLE users--",
			"admin'--",
			"' OR 1=1--",
			"1' AND '1' = '1",
			"' UNION SELECT NULL--",
			"'; EXEC xp_cmdshell('dir')--",
			"1' WAITFOR DELAY '00:00:05'--",
		},
		XSSPayloads: {
			"<script>alert('XSS')</script>",
			"<img src=x onerror=alert('XSS')>",
			"javascript:alert('XSS')",
			"<svg onload=alert('XSS')>",
			"<iframe src=javascript:alert('XSS')>",
			"'><script>alert(String.fromCharCode(88,83,83))</script>",
			"<body onload=alert('XSS')>",
		},
		CommandInject: {
			"; ls -la",
			"| whoami",
			"`id`",
			"$(whoami)",
			"& ping -c 10 127.0.0.1 &",
			"; cat /etc/passwd",
			"|| sleep 10",
		},
		PathTraversal: {
			"../../../etc/passwd",
			"..\\..\\..\\windows\\system32\\config\\sam",
			"....//....//....//etc/passwd",
			"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			"..%252f..%252f..%252fetc%252fpasswd",
			"file:///etc/passwd",
		},
		NullValues: {
			nil,
			"null",
			"NULL",
			"\x00",
			[]interface{}{nil},
		},
		LongStrings: {
			strings.Repeat("A", 1000),
			strings.Repeat("X", 10000),
			strings.Repeat("0", 50000),
			strings.Repeat("🔥", 1000),
		},
		SpecialChars: {
			"!@#$%^&*()_+-=[]{}|;':\",./<>?",
			"\n\r\t\b\f",
			"\x00\x01\x02\x03\x04\x05",
			"™€£¥¢",
			"😀🎉🔥💻🚀",
			string([]byte{0xFF, 0xFE, 0xFD}),
		},
		FormatString: {
			"%s%s%s%s%s",
			"%x%x%x%x",
			"%d%d%d%d",
			"%n",
			"%.2147483647f",
		},
		XMLInjection: {
			"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
			"<![CDATA[<script>alert('XSS')</script>]]>",
			"&lt;script&gt;alert('XSS')&lt;/script&gt;",
		},
		JSONInjection: {
			`{"$ne": null}`,
			`{"$gt": ""}`,
			`{"__proto__": {"isAdmin": true}}`,
			`{"constructor": {"prototype": {"isAdmin": true}}}`,
		},
	}
}

func (m *Mutator) Mutate(value interface{}, dataType string) []interface{} {
	mutations := []interface{}{}

	mutations = append(mutations, value)

	for _, strategy := range m.strategies {
		strategyMutations := m.applyStrategy(value, dataType, strategy)
		mutations = append(mutations, strategyMutations...)
	}

	return m.deduplicate(mutations)
}

func (m *Mutator) applyStrategy(value interface{}, dataType string, strategy MutationStrategy) []interface{} {
	mutations := []interface{}{}

	switch strategy {
	case BoundaryValues:
		mutations = m.generateBoundaryValues(dataType)
	case TypeConfusion:
		mutations = m.generateTypeConfusion(value, dataType)
	case RandomMutation:
		mutations = m.generateRandomMutations(value, dataType)
	default:
		if payloads, ok := m.payloads[strategy]; ok {
			mutations = append(mutations, payloads...)
		}
	}

	return mutations
}

func (m *Mutator) generateBoundaryValues(dataType string) []interface{} {
	switch dataType {
	case "integer", "int32", "int64":
		return []interface{}{
			0, -1, 1,
			math.MaxInt32, math.MinInt32,
			math.MaxInt64, math.MinInt64,
		}
	case "number", "float", "double":
		return []interface{}{
			0.0, -1.0, 1.0,
			math.MaxFloat32, -math.MaxFloat32,
			math.MaxFloat64, -math.MaxFloat64,
			math.NaN(), math.Inf(1), math.Inf(-1),
		}
	case "string":
		return []interface{}{
			"",
			" ",
			strings.Repeat("A", 256),
			strings.Repeat("X", 1024),
			strings.Repeat("🔥", 100),
		}
	case "boolean":
		return []interface{}{true, false, "true", "false", 1, 0}
	default:
		return []interface{}{}
	}
}

func (m *Mutator) generateTypeConfusion(value interface{}, dataType string) []interface{} {
	mutations := []interface{}{}

	switch dataType {
	case "string":
		mutations = append(mutations, 0, true, false, nil, []string{}, map[string]string{})
	case "integer", "number":
		mutations = append(mutations, "123", "true", "false", nil, []int{}, map[string]int{})
	case "boolean":
		mutations = append(mutations, "true", "false", 1, 0, "yes", "no", nil)
	case "array":
		mutations = append(mutations, nil, "{}", "[]", 0, false, "array")
	case "object":
		mutations = append(mutations, nil, "[]", "{}", 0, false, "object")
	}

	return mutations
}

func (m *Mutator) generateRandomMutations(value interface{}, dataType string) []interface{} {
	mutations := []interface{}{}

	for i := 0; i < 5; i++ {
		switch dataType {
		case "string":
			mutations = append(mutations, m.randomString())
		case "integer":
			mutations = append(mutations, m.rand.Int())
		case "number":
			mutations = append(mutations, m.rand.Float64()*1000000)
		case "boolean":
			mutations = append(mutations, m.rand.Intn(2) == 1)
		}
	}

	return mutations
}

func (m *Mutator) randomString() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
	length := m.rand.Intn(100) + 1
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[m.rand.Intn(len(charset))]
	}
	return string(b)
}

func (m *Mutator) MutateJSON(jsonData []byte) [][]byte {
	mutations := [][]byte{}

	var data interface{}
	if err := json.Unmarshal(jsonData, &data); err != nil {
		mutations = append(mutations, jsonData)
		mutations = append(mutations, []byte("{}"))
		mutations = append(mutations, []byte("null"))
		return mutations
	}

	mutations = append(mutations, jsonData)

	mutatedData := m.mutateJSONRecursive(data)
	for _, mutated := range mutatedData {
		if jsonBytes, err := json.Marshal(mutated); err == nil {
			mutations = append(mutations, jsonBytes)
		}
	}

	corruptedJSON := m.generateCorruptedJSON(jsonData)
	mutations = append(mutations, corruptedJSON...)

	return mutations
}

func (m *Mutator) mutateJSONRecursive(data interface{}) []interface{} {
	mutations := []interface{}{}

	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			mutatedValues := m.Mutate(value, m.inferType(value))
			for _, mv := range mutatedValues {
				newMap := make(map[string]interface{})
				for k, v := range v {
					newMap[k] = v
				}
				newMap[key] = mv
				mutations = append(mutations, newMap)
			}
		}

		extraFields := map[string]interface{}{
			"__proto__":   map[string]interface{}{"isAdmin": true},
			"constructor": map[string]interface{}{"prototype": map[string]interface{}{"isAdmin": true}},
			"$ne":         nil,
			"$gt":         "",
		}
		for k, extraValue := range extraFields {
			newMap := make(map[string]interface{})
			for key, value := range v {
				newMap[key] = value
			}
			newMap[k] = extraValue
			mutations = append(mutations, newMap)
		}

	case []interface{}:
		for i, elem := range v {
			mutatedValues := m.Mutate(elem, m.inferType(elem))
			for _, mv := range mutatedValues {
				newSlice := make([]interface{}, len(v))
				copy(newSlice, v)
				newSlice[i] = mv
				mutations = append(mutations, newSlice)
			}
		}

		mutations = append(mutations, []interface{}{})
		mutations = append(mutations, nil)

	default:
		mutations = append(mutations, m.Mutate(v, m.inferType(v))...)
	}

	return mutations
}

func (m *Mutator) inferType(value interface{}) string {
	switch value.(type) {
	case string:
		return "string"
	case int, int32, int64:
		return "integer"
	case float32, float64:
		return "number"
	case bool:
		return "boolean"
	case []interface{}:
		return "array"
	case map[string]interface{}:
		return "object"
	default:
		return "unknown"
	}
}

func (m *Mutator) generateCorruptedJSON(jsonData []byte) [][]byte {
	corrupted := [][]byte{}

	s := string(jsonData)
	corrupted = append(corrupted, []byte(s[:len(s)-1]))
	corrupted = append(corrupted, []byte(s+"}}"))
	corrupted = append(corrupted, []byte(strings.ReplaceAll(s, "\"", "")))
	corrupted = append(corrupted, []byte(strings.ReplaceAll(s, ":", "=")))

	return corrupted
}

func (m *Mutator) deduplicate(mutations []interface{}) []interface{} {
	seen := make(map[string]bool)
	unique := []interface{}{}

	for _, mutation := range mutations {
		key := fmt.Sprintf("%v", mutation)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, mutation)
		}
	}

	return unique
}

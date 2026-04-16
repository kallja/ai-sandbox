// Package reqconfig provides request customization for OAuth provider
// interactions. It controls query parameter ordering, extra parameters,
// token exchange headers, and body field ordering.
package reqconfig

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds all request customization options for OAuth provider
// interactions. It flows from Client A → Client B via the Intent so
// the broker knows how to format provider requests.
type Config struct {
	// ExtraParams are static key-value pairs added to the authorization URL
	// query string (e.g., {"prompt": "consent"}).
	ExtraParams map[string]string `yaml:"extra_params,omitempty" json:"extra_params,omitempty"`

	// OrderQueryParams controls the order of query string parameters in
	// the authorization URL. Parameters listed here appear first in the
	// specified order; any remaining parameters are appended alphabetically.
	OrderQueryParams []string `yaml:"order_query_params,omitempty" json:"order_query_params,omitempty"`

	// RequestHeaders are static headers added to the token exchange request
	// (e.g., {"User-Agent": "MyApp/1.0"}).
	RequestHeaders map[string]string `yaml:"request_headers,omitempty" json:"request_headers,omitempty"`

	// OrderRequestHeaders controls the order of headers in the token
	// exchange request.
	OrderRequestHeaders []string `yaml:"order_request_headers,omitempty" json:"order_request_headers,omitempty"`

	// OrderBodyFields controls the order of form fields in the token
	// exchange request body.
	OrderBodyFields []string `yaml:"order_body_fields,omitempty" json:"order_body_fields,omitempty"`
}

// LoadFile reads a YAML config file and returns a Config.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}
	return &cfg, nil
}

// Merge returns a new Config that combines base and override. Values
// in override take precedence. Nil fields in override are left as base.
// For maps, override entries win per-key. For slices, override replaces
// entirely if non-nil.
func Merge(base, override *Config) *Config {
	if base == nil {
		base = &Config{}
	}
	if override == nil {
		return base
	}

	result := *base

	if override.ExtraParams != nil {
		if result.ExtraParams == nil {
			result.ExtraParams = make(map[string]string)
		}
		for k, v := range base.ExtraParams {
			result.ExtraParams[k] = v
		}
		for k, v := range override.ExtraParams {
			result.ExtraParams[k] = v
		}
	}

	if override.OrderQueryParams != nil {
		result.OrderQueryParams = override.OrderQueryParams
	}

	if override.RequestHeaders != nil {
		if result.RequestHeaders == nil {
			result.RequestHeaders = make(map[string]string)
		}
		for k, v := range base.RequestHeaders {
			result.RequestHeaders[k] = v
		}
		for k, v := range override.RequestHeaders {
			result.RequestHeaders[k] = v
		}
	}

	if override.OrderRequestHeaders != nil {
		result.OrderRequestHeaders = override.OrderRequestHeaders
	}

	if override.OrderBodyFields != nil {
		result.OrderBodyFields = override.OrderBodyFields
	}

	return &result
}

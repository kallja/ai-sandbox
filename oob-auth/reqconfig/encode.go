package reqconfig

import (
	"net/url"
	"sort"
	"strings"
)

// EncodeQuery encodes key-value pairs as a URL query string with
// deterministic parameter ordering. Parameters listed in order appear
// first in that sequence; any remaining parameters are appended in
// alphabetical order.
func EncodeQuery(params map[string]string, order []string) string {
	seen := make(map[string]bool, len(order))
	var parts []string

	// Ordered params first.
	for _, key := range order {
		if val, ok := params[key]; ok {
			parts = append(parts, url.QueryEscape(key)+"="+url.QueryEscape(val))
			seen[key] = true
		}
	}

	// Remaining params in alphabetical order.
	var remaining []string
	for key := range params {
		if !seen[key] {
			remaining = append(remaining, key)
		}
	}
	sort.Strings(remaining)
	for _, key := range remaining {
		parts = append(parts, url.QueryEscape(key)+"="+url.QueryEscape(params[key]))
	}

	return strings.Join(parts, "&")
}

// EncodeForm encodes key-value pairs as a URL-encoded form body with
// deterministic field ordering. Fields listed in order appear first;
// any remaining fields are appended alphabetically.
func EncodeForm(fields map[string]string, order []string) string {
	seen := make(map[string]bool, len(order))
	var parts []string

	for _, key := range order {
		if val, ok := fields[key]; ok {
			parts = append(parts, url.QueryEscape(key)+"="+url.QueryEscape(val))
			seen[key] = true
		}
	}

	var remaining []string
	for key := range fields {
		if !seen[key] {
			remaining = append(remaining, key)
		}
	}
	sort.Strings(remaining)
	for _, key := range remaining {
		parts = append(parts, url.QueryEscape(key)+"="+url.QueryEscape(fields[key]))
	}

	return strings.Join(parts, "&")
}

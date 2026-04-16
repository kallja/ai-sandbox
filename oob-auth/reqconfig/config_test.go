package reqconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFile(t *testing.T) {
	yaml := `
extra_params:
  prompt: consent
  access_type: offline
order_query_params:
  - response_type
  - client_id
  - scope
request_headers:
  User-Agent: "MyApp/1.0"
order_request_headers:
  - Content-Type
  - User-Agent
order_body_fields:
  - grant_type
  - code
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(yaml), 0644)

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	if cfg.ExtraParams["prompt"] != "consent" {
		t.Errorf("ExtraParams[prompt] = %q, want %q", cfg.ExtraParams["prompt"], "consent")
	}
	if cfg.ExtraParams["access_type"] != "offline" {
		t.Errorf("ExtraParams[access_type] = %q, want %q", cfg.ExtraParams["access_type"], "offline")
	}
	if len(cfg.OrderQueryParams) != 3 {
		t.Fatalf("OrderQueryParams length = %d, want 3", len(cfg.OrderQueryParams))
	}
	if cfg.OrderQueryParams[1] != "client_id" {
		t.Errorf("OrderQueryParams[1] = %q, want %q", cfg.OrderQueryParams[1], "client_id")
	}
	if cfg.RequestHeaders["User-Agent"] != "MyApp/1.0" {
		t.Errorf("RequestHeaders[User-Agent] = %q", cfg.RequestHeaders["User-Agent"])
	}
	if len(cfg.OrderRequestHeaders) != 2 {
		t.Fatalf("OrderRequestHeaders length = %d, want 2", len(cfg.OrderRequestHeaders))
	}
	if len(cfg.OrderBodyFields) != 2 {
		t.Fatalf("OrderBodyFields length = %d, want 2", len(cfg.OrderBodyFields))
	}
}

func TestLoadFile_NotFound(t *testing.T) {
	_, err := LoadFile("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadFile_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte("{{{{not yaml"), 0644)

	_, err := LoadFile(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadFile_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yaml")
	os.WriteFile(path, []byte(""), 0644)

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.ExtraParams != nil {
		t.Errorf("ExtraParams should be nil for empty config")
	}
}

func TestMerge_OverrideWins(t *testing.T) {
	base := &Config{
		ExtraParams:      map[string]string{"a": "1", "b": "2"},
		OrderQueryParams: []string{"a", "b"},
	}
	override := &Config{
		ExtraParams:      map[string]string{"b": "override", "c": "3"},
		OrderQueryParams: []string{"x", "y"},
	}

	result := Merge(base, override)

	if result.ExtraParams["a"] != "1" {
		t.Errorf("ExtraParams[a] = %q, want %q", result.ExtraParams["a"], "1")
	}
	if result.ExtraParams["b"] != "override" {
		t.Errorf("ExtraParams[b] = %q, want %q", result.ExtraParams["b"], "override")
	}
	if result.ExtraParams["c"] != "3" {
		t.Errorf("ExtraParams[c] = %q, want %q", result.ExtraParams["c"], "3")
	}
	if len(result.OrderQueryParams) != 2 || result.OrderQueryParams[0] != "x" {
		t.Errorf("OrderQueryParams = %v, want [x y]", result.OrderQueryParams)
	}
}

func TestMerge_NilOverride(t *testing.T) {
	base := &Config{
		ExtraParams: map[string]string{"a": "1"},
	}
	result := Merge(base, nil)
	if result.ExtraParams["a"] != "1" {
		t.Errorf("ExtraParams[a] = %q, want %q", result.ExtraParams["a"], "1")
	}
}

func TestMerge_NilBase(t *testing.T) {
	override := &Config{
		OrderBodyFields: []string{"grant_type"},
	}
	result := Merge(nil, override)
	if len(result.OrderBodyFields) != 1 {
		t.Errorf("OrderBodyFields length = %d, want 1", len(result.OrderBodyFields))
	}
}

func TestMerge_PartialOverride(t *testing.T) {
	base := &Config{
		OrderQueryParams:    []string{"a"},
		OrderRequestHeaders: []string{"Content-Type"},
	}
	override := &Config{
		OrderQueryParams: []string{"b", "c"},
		// OrderRequestHeaders is nil — should keep base.
	}
	result := Merge(base, override)

	if len(result.OrderQueryParams) != 2 || result.OrderQueryParams[0] != "b" {
		t.Errorf("OrderQueryParams = %v, want [b c]", result.OrderQueryParams)
	}
	if len(result.OrderRequestHeaders) != 1 || result.OrderRequestHeaders[0] != "Content-Type" {
		t.Errorf("OrderRequestHeaders = %v, want [Content-Type]", result.OrderRequestHeaders)
	}
}

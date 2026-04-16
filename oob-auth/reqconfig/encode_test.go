package reqconfig

import (
	"strings"
	"testing"
)

func TestEncodeQuery_OrderedParams(t *testing.T) {
	params := map[string]string{
		"response_type": "code",
		"client_id":     "my-client",
		"scope":         "read write",
		"state":         "abc",
	}
	order := []string{"response_type", "client_id", "state", "scope"}

	got := EncodeQuery(params, order)

	// Verify ordering: response_type first, client_id second, etc.
	parts := strings.Split(got, "&")
	if len(parts) != 4 {
		t.Fatalf("got %d parts, want 4: %s", len(parts), got)
	}

	expected := []string{
		"response_type=code",
		"client_id=my-client",
		"state=abc",
		"scope=read+write",
	}
	for i, want := range expected {
		if parts[i] != want {
			t.Errorf("parts[%d] = %q, want %q", i, parts[i], want)
		}
	}
}

func TestEncodeQuery_UnorderedParamsAppendedAlphabetically(t *testing.T) {
	params := map[string]string{
		"z_param": "z",
		"a_param": "a",
		"m_param": "m",
	}

	got := EncodeQuery(params, nil)
	parts := strings.Split(got, "&")

	if len(parts) != 3 {
		t.Fatalf("got %d parts, want 3", len(parts))
	}
	if parts[0] != "a_param=a" {
		t.Errorf("parts[0] = %q, want a_param=a", parts[0])
	}
	if parts[1] != "m_param=m" {
		t.Errorf("parts[1] = %q, want m_param=m", parts[1])
	}
	if parts[2] != "z_param=z" {
		t.Errorf("parts[2] = %q, want z_param=z", parts[2])
	}
}

func TestEncodeQuery_MixedOrderedAndUnordered(t *testing.T) {
	params := map[string]string{
		"first":  "1",
		"second": "2",
		"alpha":  "a",
		"beta":   "b",
	}
	order := []string{"second", "first"}

	got := EncodeQuery(params, order)
	parts := strings.Split(got, "&")

	if len(parts) != 4 {
		t.Fatalf("got %d parts, want 4", len(parts))
	}
	// Ordered: second, first
	if parts[0] != "second=2" {
		t.Errorf("parts[0] = %q, want second=2", parts[0])
	}
	if parts[1] != "first=1" {
		t.Errorf("parts[1] = %q, want first=1", parts[1])
	}
	// Unordered alphabetically: alpha, beta
	if parts[2] != "alpha=a" {
		t.Errorf("parts[2] = %q, want alpha=a", parts[2])
	}
	if parts[3] != "beta=b" {
		t.Errorf("parts[3] = %q, want beta=b", parts[3])
	}
}

func TestEncodeQuery_OrderWithMissingParams(t *testing.T) {
	params := map[string]string{
		"a": "1",
	}
	order := []string{"b", "a", "c"}

	got := EncodeQuery(params, order)
	if got != "a=1" {
		t.Errorf("got %q, want %q", got, "a=1")
	}
}

func TestEncodeQuery_Empty(t *testing.T) {
	got := EncodeQuery(map[string]string{}, nil)
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestEncodeQuery_URLEncoding(t *testing.T) {
	params := map[string]string{
		"redirect_uri": "http://localhost/callback",
	}

	got := EncodeQuery(params, nil)
	if !strings.Contains(got, "redirect_uri=http%3A%2F%2Flocalhost%2Fcallback") {
		t.Errorf("got %q, expected URL encoding", got)
	}
}

func TestEncodeForm_OrderedFields(t *testing.T) {
	fields := map[string]string{
		"grant_type":   "authorization_code",
		"code":         "abc123",
		"client_id":    "my-client",
		"redirect_uri": "http://localhost/cb",
	}
	order := []string{"grant_type", "code", "client_id", "redirect_uri"}

	got := EncodeForm(fields, order)
	parts := strings.Split(got, "&")

	if len(parts) != 4 {
		t.Fatalf("got %d parts, want 4", len(parts))
	}
	if parts[0] != "grant_type=authorization_code" {
		t.Errorf("parts[0] = %q", parts[0])
	}
	if parts[1] != "code=abc123" {
		t.Errorf("parts[1] = %q", parts[1])
	}
}

func TestEncodeForm_NoOrder(t *testing.T) {
	fields := map[string]string{
		"z": "3",
		"a": "1",
	}
	got := EncodeForm(fields, nil)
	if got != "a=1&z=3" {
		t.Errorf("got %q, want %q", got, "a=1&z=3")
	}
}

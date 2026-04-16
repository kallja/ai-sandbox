package clientb

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/kallja/ai-sandbox/oob-auth/crypto"
	"github.com/kallja/ai-sandbox/oob-auth/protocol"
	"github.com/kallja/ai-sandbox/oob-auth/reqconfig"
)

// OAuthExecutor handles the OAuth authorization flow. In production
// this opens a browser or presents a URL; in tests it's replaced with
// a mock that returns a known auth code.
type OAuthExecutor interface {
	// Authorize performs the OAuth flow described by the intent and
	// returns the resulting authorization code.
	Authorize(ctx context.Context, intent *protocol.Intent) (authCode string, err error)
}

// TokenRedeemer exchanges an authorization code for tokens.
type TokenRedeemer interface {
	// Redeem exchanges an auth code for tokens using default request formatting.
	Redeem(ctx context.Context, tokenURL, clientID, authCode, redirectURI string) (*protocol.Response, error)

	// RedeemWithConfig exchanges an auth code for tokens with custom request
	// formatting (header ordering, body field ordering, extra headers).
	RedeemWithConfig(ctx context.Context, tokenURL, clientID, authCode, redirectURI string, cfg *reqconfig.Config) (*protocol.Response, error)
}

// HTTPTokenRedeemer redeems auth codes via HTTP POST to the token endpoint.
type HTTPTokenRedeemer struct {
	Client *http.Client
}

// Redeem exchanges an authorization code for tokens at the given token endpoint.
func (r *HTTPTokenRedeemer) Redeem(ctx context.Context, tokenURL, clientID, authCode, redirectURI string) (*protocol.Response, error) {
	return r.RedeemWithConfig(ctx, tokenURL, clientID, authCode, redirectURI, nil)
}

// RedeemWithConfig exchanges an authorization code for tokens, applying
// request customization from the config (custom headers, header ordering,
// body field ordering).
func (r *HTTPTokenRedeemer) RedeemWithConfig(ctx context.Context, tokenURL, clientID, authCode, redirectURI string, cfg *reqconfig.Config) (*protocol.Response, error) {
	fields := map[string]string{
		"grant_type":   "authorization_code",
		"code":         authCode,
		"client_id":    clientID,
		"redirect_uri": redirectURI,
	}

	var bodyStr string
	if cfg != nil && len(cfg.OrderBodyFields) > 0 {
		bodyStr = reqconfig.EncodeForm(fields, cfg.OrderBodyFields)
	} else {
		bodyStr = reqconfig.EncodeForm(fields, nil)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(bodyStr))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Apply custom headers.
	if cfg != nil {
		for k, v := range cfg.RequestHeaders {
			req.Header.Set(k, v)
		}
		// Apply header ordering by rebuilding the header map.
		if len(cfg.OrderRequestHeaders) > 0 {
			applyHeaderOrder(req, cfg.OrderRequestHeaders)
		}
	}

	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return &protocol.Response{Error: fmt.Sprintf("token endpoint returned %d: %s", resp.StatusCode, body)}, nil
	}

	// Parse the token response. We treat tokens as opaque strings
	// (no JWT validation per spec).
	tokenResp, err := protocol.UnmarshalResponse(body)
	if err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}
	return tokenResp, nil
}

// applyHeaderOrder reorders HTTP headers so that keys listed in order
// appear first. Go's http.Header is a map so iteration order is not
// guaranteed, but many servers are sensitive to header order in the
// raw wire format. We rebuild the header map in the desired order.
func applyHeaderOrder(req *http.Request, order []string) {
	original := req.Header.Clone()
	req.Header = make(http.Header)
	seen := make(map[string]bool)

	for _, key := range order {
		canonical := http.CanonicalHeaderKey(key)
		if vals, ok := original[canonical]; ok {
			req.Header[canonical] = vals
			seen[canonical] = true
		}
	}

	// Append remaining headers alphabetically.
	var remaining []string
	for key := range original {
		if !seen[key] {
			remaining = append(remaining, key)
		}
	}
	sort.Strings(remaining)
	for _, key := range remaining {
		req.Header[key] = original[key]
	}
}

// URLPresenter is a simple OAuthExecutor that prints the authorization URL
// and waits for the user to paste back the auth code.
type URLPresenter struct {
	// PromptFunc reads the auth code from the user. If nil, reads from stdin.
	PromptFunc func(ctx context.Context, authURL string) (string, error)
}

// Authorize builds the authorization URL and prompts the user to complete
// the flow, then returns the resulting authorization code.
func (p *URLPresenter) Authorize(ctx context.Context, intent *protocol.Intent) (string, error) {
	authURL, err := buildAuthURL(intent)
	if err != nil {
		return "", err
	}

	if p.PromptFunc != nil {
		return p.PromptFunc(ctx, authURL)
	}

	fmt.Printf("\nOpen this URL to authorize:\n  %s\n\n", authURL)
	fmt.Print("Paste the authorization code: ")
	var code string
	if _, err := fmt.Scanln(&code); err != nil {
		return "", fmt.Errorf("read auth code: %w", err)
	}
	return code, nil
}

func buildAuthURL(intent *protocol.Intent) (string, error) {
	u, err := url.Parse(intent.AuthURL)
	if err != nil {
		return "", fmt.Errorf("parse auth URL: %w", err)
	}

	// Collect all query parameters.
	params := make(map[string]string)

	// Preserve any params already in the base URL.
	for k, v := range u.Query() {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}

	// Standard OAuth params.
	params["response_type"] = "code"
	params["client_id"] = intent.ClientID
	params["redirect_uri"] = intent.RedirectURI
	params["code_challenge"] = intent.CodeChallenge
	params["code_challenge_method"] = intent.ChallengeMethod
	params["state"] = intent.State
	if len(intent.Scopes) > 0 {
		params["scope"] = strings.Join(intent.Scopes, " ")
	}

	// Extra static params from request config.
	for k, v := range intent.ExtraParams {
		params[k] = v
	}

	u.RawQuery = reqconfig.EncodeQuery(params, intent.OrderQueryParams)
	return u.String(), nil
}

// zeroString overwrites the backing bytes of a string to limit memory exposure.
// This is best-effort — the Go runtime may have copied the string elsewhere.
func zeroString(s *string) {
	b := []byte(*s)
	crypto.Zero(b)
	*s = ""
}

package clientb

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kallja/ai-sandbox/oob-auth/crypto"
	"github.com/kallja/ai-sandbox/oob-auth/protocol"
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
	// Redeem exchanges an auth code + PKCE verifier for tokens.
	// Note: the Broker does not have the verifier in the code-relay mode.
	// When acting in full-token mode, it redeems the code itself.
	Redeem(ctx context.Context, tokenURL, clientID, authCode, redirectURI string) (*protocol.Response, error)
}

// HTTPTokenRedeemer redeems auth codes via HTTP POST to the token endpoint.
type HTTPTokenRedeemer struct {
	Client *http.Client
}

// Redeem exchanges an authorization code for tokens at the given token endpoint.
func (r *HTTPTokenRedeemer) Redeem(ctx context.Context, tokenURL, clientID, authCode, redirectURI string) (*protocol.Response, error) {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authCode},
		"client_id":    {clientID},
		"redirect_uri": {redirectURI},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", intent.ClientID)
	q.Set("redirect_uri", intent.RedirectURI)
	q.Set("code_challenge", intent.CodeChallenge)
	q.Set("code_challenge_method", intent.ChallengeMethod)
	q.Set("state", intent.State)
	if len(intent.Scopes) > 0 {
		q.Set("scope", strings.Join(intent.Scopes, " "))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// zeroString overwrites the backing bytes of a string to limit memory exposure.
// This is best-effort — the Go runtime may have copied the string elsewhere.
func zeroString(s *string) {
	b := []byte(*s)
	crypto.Zero(b)
	*s = ""
}

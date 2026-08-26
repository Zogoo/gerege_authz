// Package oidcauth drives the OIDC authorization-code flow and validates
// access tokens locally.
//
// Two departures from the existing cityos sample, both from mvp_docs/07:
//
//   - §3.4 token validation is local. The sample introspected against Keycloak
//     on every session-bearing request; this validates the signature against
//     Keycloak's published keys and calls Keycloak only for the code exchange
//     and refresh. A Keycloak outage then degrades new logins rather than all
//     traffic.
//   - §3.6 PKCE is used, and `state` and `nonce` are verified on the callback.
//     Cheap at the start, awkward to retrofit.
//
// The two-URL split (mvp_docs/06 hazard 4) is explicit rather than discovered:
// the browser is sent to the external issuer, back-channel calls go to the
// in-cluster address, and VerifyIssuer checks at startup that Keycloak agrees
// about which issuer it is. Getting this wrong fails token validation with an
// error that points at the wrong thing.
package oidcauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/gerege/idp-mvp/internal/config"
)

// Claims are the parts of an access token the authorizer acts on.
type Claims struct {
	Subject           string `json:"sub"`
	AuthorizedParty   string `json:"azp"`
	PreferredUsername string `json:"preferred_username"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	Name              string `json:"name"`
	Expiry            int64  `json:"exp"`
	SessionID         string `json:"sid"`
	// AuthContextClass is Keycloak's `acr`: 1 when the user actively
	// authenticated, 0 when the request was answered from an existing SSO
	// session without re-prompting. Carried through token exchange, which is
	// why an agent inherits it and the step-up gate must not rely on it alone.
	AuthContextClass string `json:"acr"`
}

// ACR returns the authentication context class as a number, or -1 when absent
// or unparseable. Absent means "cannot demonstrate a fresh authentication",
// which for a step-up route is a refusal.
func (c Claims) ACR() int {
	if c.AuthContextClass == "" {
		return -1
	}
	n, err := strconv.Atoi(c.AuthContextClass)
	if err != nil {
		return -1
	}
	return n
}

func (c Claims) Display() string {
	if c.Name != "" {
		return c.Name
	}
	if c.GivenName != "" || c.FamilyName != "" {
		return strings.TrimSpace(c.GivenName + " " + c.FamilyName)
	}
	return c.PreferredUsername
}

// Provider holds everything needed to run the flow.
type Provider struct {
	issuer   config.Issuer
	verifier *oidc.IDTokenVerifier
	http     *http.Client
}

// New builds a provider without using OIDC discovery.
//
// Discovery is skipped on purpose: with KC_HOSTNAME pointing at the browser
// hostname, the discovery document reports external URLs for *every* endpoint,
// including the token and JWKS endpoints that must be called from inside the
// cluster. Configuring the four URLs explicitly is clearer than fetching a
// document and then rewriting half of it.
func New(issuer config.Issuer, hc *http.Client) *Provider {
	ctx := oidc.ClientContext(context.Background(), hc)
	keys := oidc.NewRemoteKeySet(ctx, issuer.JWKSURL())
	return &Provider{
		issuer: issuer,
		http:   hc,
		verifier: oidc.NewVerifier(issuer.External, keys, &oidc.Config{
			// Keycloak access tokens carry no `aud` for these clients, and
			// ext-authz validates tokens issued to several clients. The
			// application identity is taken from `azp` and checked against the
			// configured application registry instead — see decision.Pipeline.
			SkipClientIDCheck: true,
			SupportedSigningAlgs: []string{
				oidc.RS256, oidc.RS384, oidc.RS512,
				oidc.ES256, oidc.ES384, oidc.ES512,
			},
		}),
	}
}

// VerifyIssuer asserts that Keycloak, asked over the in-cluster address,
// reports the external issuer. A mismatch here is mvp_docs/06 hazard 4 and
// causes more lost time than the rest combined, so ext-authz refuses to start.
func (p *Provider) VerifyIssuer(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.issuer.DiscoveryURL(), nil)
	if err != nil {
		return err
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", p.issuer.DiscoveryURL(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery %s returned %d", p.issuer.DiscoveryURL(), resp.StatusCode)
	}
	var doc struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("decode discovery document: %w", err)
	}
	if doc.Issuer != p.issuer.External {
		return fmt.Errorf(
			"issuer mismatch: Keycloak reports %q but issuer.external is %q. "+
				"Tokens will fail validation. Set KC_HOSTNAME to the browser-facing URL",
			doc.Issuer, p.issuer.External)
	}
	return nil
}

// Verify validates a JWT locally and returns its claims.
func (p *Provider) Verify(ctx context.Context, raw string) (*Claims, error) {
	tok, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	var c Claims
	if err := tok.Claims(&c); err != nil {
		return nil, err
	}
	if c.Subject == "" {
		return nil, fmt.Errorf("token has no subject")
	}
	if c.AuthorizedParty == "" {
		// Without azp there is no application, and consent cannot be evaluated
		// against anything. Refuse rather than guess.
		return nil, fmt.Errorf("token has no azp claim")
	}
	return &c, nil
}

// PKCE is one authorization request's proof key.
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE generates an S256 code verifier and challenge.
func NewPKCE() (PKCE, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return PKCE{}, err
	}
	v := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(v))
	return PKCE{Verifier: v, Challenge: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

// RandomString returns an unguessable value for `state` and `nonce`.
func RandomString() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AuthorizationURL builds the browser redirect target.
func (p *Provider) AuthorizationURL(clientID, redirectURI, state, nonce string, pk PKCE) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid profile email")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", pk.Challenge)
	q.Set("code_challenge_method", "S256")
	return p.issuer.AuthorizationURL() + "?" + q.Encode()
}

// LogoutURL ends the Keycloak SSO session. Single sign-on implies single
// sign-out (Scenario 1, step 5).
func (p *Provider) LogoutURL(idToken, postLogoutRedirect string) string {
	q := url.Values{}
	if idToken != "" {
		q.Set("id_token_hint", idToken)
	}
	if postLogoutRedirect != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirect)
	}
	return p.issuer.EndSessionURL() + "?" + q.Encode()
}

// Tokens is a token endpoint response.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// Exchange trades an authorization code for tokens, over the in-cluster URL.
func (p *Provider) Exchange(ctx context.Context, clientID, clientSecret, code, redirectURI, verifier string) (*Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", verifier)
	return p.post(ctx, form)
}

// Refresh renews an expired access token.
//
// mvp_docs/04 §3: a failed refresh means the session is no longer valid. The
// sample logged the failure and continued through the function; here the caller
// treats an error as unauthenticated and restarts the flow.
func (p *Provider) Refresh(ctx context.Context, clientID, clientSecret, refreshToken string) (*Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	return p.post(ctx, form)
}

func (p *Provider) post(ctx context.Context, form url.Values) (*Tokens, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.issuer.TokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var t Tokens
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return nil, fmt.Errorf("decode token response (%d): %w", resp.StatusCode, err)
	}
	if t.Error != "" {
		return nil, fmt.Errorf("token endpoint: %s: %s", t.Error, t.ErrorDesc)
	}
	if t.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint returned %d with no access token", resp.StatusCode)
	}
	return &t, nil
}

// VerifyNonce checks the ID token's nonce against the one issued with the
// authorization request.
func (p *Provider) VerifyNonce(ctx context.Context, idToken, want string) error {
	tok, err := p.verifier.Verify(ctx, idToken)
	if err != nil {
		return fmt.Errorf("id token: %w", err)
	}
	if tok.Nonce != want {
		return fmt.Errorf("id token nonce mismatch")
	}
	return nil
}

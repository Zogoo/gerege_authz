package decision

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gerege/idp-mvp/internal/config"
	"github.com/gerege/idp-mvp/internal/logx"
	"github.com/gerege/idp-mvp/internal/oidcauth"
	"github.com/gerege/idp-mvp/internal/session"
)

const (
	kindUser   = "user"
	kindSystem = "system_principal"
	kindAgent  = "agent"
)

// identity is the resolved trio from mvp_docs/02 §3, minus the workload, which
// travels on the Request because it comes from the transport rather than from a
// token.
type identity struct {
	kind        string // user | system_principal | agent
	subjectType string // gerege/user | gerege/system_principal
	subject     string
	application string // the consent counterparty
	display     string
	accessToken string

	// agent is the gerege/agent object id when an agent is acting for the
	// principal. The principal stays the human: an agent does not replace the
	// person it acts for, it is added alongside them. This is the distinction
	// legacy IAM cannot draw, and the reason an agent's actions are otherwise
	// indistinguishable from the human's in an audit record.
	agent string
	// acr is the authentication context class of the underlying login, carried
	// through token exchange. Used by the step-up gate.
	acr int
}

// identify runs steps 2 and 3. A non-nil Response means the pipeline stops
// here: either the browser is being sent to Keycloak, or the caller is denied.
func (p *Pipeline) identify(ctx context.Context, req Request, rule *config.Rule, matched bool, d *logx.Decision) (identity, *Response) {
	authMode := config.AuthModeEither
	if matched {
		authMode = rule.AuthMode
	}

	if raw := bearerToken(req); raw != "" && authMode != config.AuthModeSession {
		claims, err := p.oidc.Verify(ctx, raw)
		if err != nil {
			logx.Error("bearer token rejected", "err", err.Error())
			return identity{}, &Response{Outcome: Deny, Status: 401, Reason: logx.ReasonTokenInvalid,
				Body: denyBody(logx.ReasonTokenInvalid, "the presented token is not valid")}
		}
		id, resp := p.fromClaims(claims, raw)
		if resp != nil {
			return identity{}, resp
		}
		return id, nil
	}

	if authMode == config.AuthModeBearer {
		return identity{}, &Response{Outcome: Deny, Status: 401, Reason: logx.ReasonNoSession,
			Body: denyBody(logx.ReasonNoSession, "this endpoint requires a bearer token")}
	}

	sid := cookieValue(req.header("cookie"), p.cfg.Cookie.Name)
	if sid == "" {
		return identity{}, p.startLogin(ctx, req, d)
	}

	sess, err := p.sessions.Get(ctx, sid)
	if err != nil {
		// A session store failure and a missing session are the same thing
		// here: the session cannot be verified, so it does not exist.
		return identity{}, p.startLogin(ctx, req, d)
	}
	if !sess.Authenticated {
		return identity{}, p.startLogin(ctx, req, d)
	}

	if time.Now().After(sess.ExpiresAt.Add(-15 * time.Second)) {
		app, ok := p.cfg.AppByName(sess.Application)
		if !ok {
			return identity{}, p.startLogin(ctx, req, d)
		}
		tok, rerr := p.oidc.Refresh(ctx, app.Name, app.ClientSecret, sess.RefreshToken)
		if rerr != nil {
			// mvp_docs/04 §3: a failed refresh means the session is no longer
			// valid. Restart authentication — never continue as authenticated.
			logx.Error("token refresh failed; restarting authentication", "err", rerr.Error())
			_ = p.sessions.Delete(ctx, sid)
			return identity{}, p.startLogin(ctx, req, d)
		}
		sess.AccessToken = tok.AccessToken
		if tok.RefreshToken != "" {
			sess.RefreshToken = tok.RefreshToken
		}
		sess.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
		if err := p.sessions.Put(ctx, sess, p.cfg.Cookie.TTL); err != nil {
			return identity{}, &Response{Outcome: Deny, Status: 403, Reason: logx.ReasonInternalError,
				Body: denyBody(logx.ReasonInternalError, "session could not be persisted")}
		}
	}

	claims, err := p.oidc.Verify(ctx, sess.AccessToken)
	if err != nil {
		logx.Error("session access token failed validation", "err", err.Error())
		_ = p.sessions.Delete(ctx, sid)
		return identity{}, p.startLogin(ctx, req, d)
	}
	id, resp := p.fromClaims(claims, sess.AccessToken)
	if resp != nil {
		return identity{}, resp
	}
	return id, nil
}

// fromClaims turns validated claims into a principal, an application and — when
// the token came out of an RFC 8693 exchange — an agent.
func (p *Pipeline) fromClaims(c *oidcauth.Claims, raw string) (identity, *Response) {
	// An agent's token has `sub` = the human and `azp` = the agent. Nothing
	// else distinguishes it from the human's own token, which is precisely why
	// the agent registry is configuration rather than inference.
	if ag, ok := p.cfg.AgentByClient(c.AuthorizedParty); ok {
		return identity{
			kind:        kindAgent,
			subjectType: "gerege/user",
			subject:     c.Subject,
			application: c.AuthorizedParty,
			display:     c.Display(),
			accessToken: raw,
			agent:       ag.Object,
			acr:         c.ACR(),
		}, nil
	}

	// A non-human caller is identified by static configuration rather than by
	// sniffing the token, because "is this a device" is a deployment fact.
	// mvp_docs/02 §4.4: no user, no consent — the device acts on its own
	// relationships.
	if spID, ok := p.cfg.SystemPrincipals[c.AuthorizedParty]; ok {
		return identity{
			kind:        kindSystem,
			subjectType: "gerege/system_principal",
			subject:     spID,
			application: c.AuthorizedParty,
			display:     spID,
			accessToken: raw,
		}, nil
	}
	if _, ok := p.cfg.AppByName(c.AuthorizedParty); !ok {
		// An application the authorizer has never heard of cannot have a
		// consent grant, so there is nothing to evaluate. Deny rather than
		// treat it as first-party.
		logx.Error("token from unregistered application", "azp", c.AuthorizedParty)
		return identity{}, &Response{Outcome: Deny, Status: 403, Reason: logx.ReasonUnknownApplication,
			Body: denyBody(logx.ReasonUnknownApplication,
				fmt.Sprintf("application %q is not registered with the authorizer", c.AuthorizedParty))}
	}
	return identity{
		kind:        kindUser,
		subjectType: "gerege/user",
		subject:     c.Subject,
		application: c.AuthorizedParty,
		display:     c.Display(),
		accessToken: raw,
		acr:         c.ACR(),
	}, nil
}

// startLogin begins the OIDC authorization-code flow for a browser, or denies
// for anything else. The decision between the two is the Accept header: a
// fetch/XHR client that follows a 302 to Keycloak's HTML login page learns
// nothing useful, and a redirect loop on /favicon.ico is a classic way to lose
// an afternoon.
func (p *Pipeline) startLogin(ctx context.Context, req Request, d *logx.Decision) *Response {
	app, ok := p.cfg.AppForHost(req.Host)
	if !ok || !wantsHTML(req) {
		return &Response{Outcome: Deny, Status: 401, Reason: logx.ReasonNoSession,
			Body: denyBody(logx.ReasonNoSession, "authentication required")}
	}
	d.Application = app.Name

	state, err1 := oidcauth.RandomString()
	nonce, err2 := oidcauth.RandomString()
	pk, err3 := oidcauth.NewPKCE()
	sid, err4 := session.NewID()
	if err := firstErr(err1, err2, err3, err4); err != nil {
		logx.Error("cannot start OIDC flow", "err", err.Error())
		return &Response{Outcome: Deny, Status: 403, Reason: logx.ReasonInternalError,
			Body: denyBody(logx.ReasonInternalError, "login could not be started")}
	}

	pending := &session.Session{
		ID:           sid,
		Application:  app.Name,
		State:        state,
		Nonce:        nonce,
		CodeVerifier: pk.Verifier,
		ReturnTo:     externalURL(req),
	}
	if err := p.sessions.New(ctx, pending, p.cfg.Cookie.PendTTL); err != nil {
		logx.Error("cannot persist pending session", "err", err.Error())
		return &Response{Outcome: Deny, Status: 403, Reason: logx.ReasonInternalError,
			Body: denyBody(logx.ReasonInternalError, "login could not be started")}
	}

	return &Response{
		Outcome:   Redirect,
		Status:    http.StatusFound,
		Reason:    logx.ReasonRedirectToLogin,
		Location:  p.oidc.AuthorizationURL(app.Name, redirectURI(req), state, nonce, pk),
		SetCookie: p.cookie(sid, p.cfg.Cookie.PendTTL),
	}
}

func (p *Pipeline) handleCallback(ctx context.Context, req Request, d *logx.Decision) Response {
	q := queryValues(req.Path)
	code, state := q.Get("code"), q.Get("state")
	if e := q.Get("error"); e != "" {
		return Response{Outcome: Deny, Status: 403, Reason: logx.ReasonTokenInvalid,
			Body: denyBody(logx.ReasonTokenInvalid, "identity provider returned "+e)}
	}

	sid := cookieValue(req.header("cookie"), p.cfg.Cookie.Name)
	if sid == "" || code == "" || state == "" {
		return Response{Outcome: Deny, Status: 400, Reason: logx.ReasonTokenInvalid,
			Body: denyBody(logx.ReasonTokenInvalid, "malformed callback")}
	}
	sess, err := p.sessions.Get(ctx, sid)
	if err != nil {
		return Response{Outcome: Deny, Status: 400, Reason: logx.ReasonNoSession,
			Body: denyBody(logx.ReasonNoSession, "login session expired — start again")}
	}
	// `state` is bound to this browser through the cookie, so a state value
	// captured elsewhere is useless.
	if sess.State == "" || sess.State != state {
		logx.Error("oidc state mismatch", "session", sid)
		return Response{Outcome: Deny, Status: 400, Reason: logx.ReasonTokenInvalid,
			Body: denyBody(logx.ReasonTokenInvalid, "state mismatch")}
	}
	app, ok := p.cfg.AppByName(sess.Application)
	if !ok {
		return Response{Outcome: Deny, Status: 403, Reason: logx.ReasonUnknownApplication,
			Body: denyBody(logx.ReasonUnknownApplication, "unknown application")}
	}
	d.Application = app.Name

	tok, err := p.oidc.Exchange(ctx, app.Name, app.ClientSecret, code, redirectURI(req), sess.CodeVerifier)
	if err != nil {
		logx.Error("code exchange failed", "err", err.Error())
		return Response{Outcome: Deny, Status: 403, Reason: logx.ReasonTokenInvalid,
			Body: denyBody(logx.ReasonTokenInvalid, "code exchange failed")}
	}
	if tok.IDToken != "" {
		if err := p.oidc.VerifyNonce(ctx, tok.IDToken, sess.Nonce); err != nil {
			logx.Error("nonce verification failed", "err", err.Error())
			return Response{Outcome: Deny, Status: 403, Reason: logx.ReasonTokenInvalid,
				Body: denyBody(logx.ReasonTokenInvalid, "nonce mismatch")}
		}
	}
	claims, err := p.oidc.Verify(ctx, tok.AccessToken)
	if err != nil {
		logx.Error("access token from callback failed validation", "err", err.Error())
		return Response{Outcome: Deny, Status: 403, Reason: logx.ReasonTokenInvalid,
			Body: denyBody(logx.ReasonTokenInvalid, "token validation failed")}
	}

	returnTo := sess.ReturnTo
	if returnTo == "" {
		returnTo = req.Scheme + "://" + req.Host + "/"
	}
	// A fresh identifier on privilege change: the pending session becomes an
	// authenticated one under a new id.
	newID, err := session.NewID()
	if err != nil {
		return Response{Outcome: Deny, Status: 403, Reason: logx.ReasonInternalError,
			Body: denyBody(logx.ReasonInternalError, "session could not be created")}
	}
	_ = p.sessions.Delete(ctx, sid)
	authed := &session.Session{
		ID:            newID,
		Application:   app.Name,
		Authenticated: true,
		AccessToken:   tok.AccessToken,
		RefreshToken:  tok.RefreshToken,
		IDToken:       tok.IDToken,
		ExpiresAt:     time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second),
		Subject:       claims.Subject,
		DisplayName:   claims.Display(),
	}
	if err := p.sessions.Put(ctx, authed, p.cfg.Cookie.TTL); err != nil {
		return Response{Outcome: Deny, Status: 403, Reason: logx.ReasonInternalError,
			Body: denyBody(logx.ReasonInternalError, "session could not be persisted")}
	}
	d.Principal = claims.Subject
	d.Kind = kindUser

	return Response{
		Outcome:   Redirect,
		Status:    http.StatusFound,
		Reason:    "authenticated",
		Location:  returnTo,
		SetCookie: p.cookie(newID, p.cfg.Cookie.TTL),
	}
}

func (p *Pipeline) handleLogout(ctx context.Context, req Request, d *logx.Decision) Response {
	var idToken string
	if sid := cookieValue(req.header("cookie"), p.cfg.Cookie.Name); sid != "" {
		if sess, err := p.sessions.Get(ctx, sid); err == nil {
			idToken = sess.IDToken
			d.Principal = sess.Subject
			d.Application = sess.Application
		}
		_ = p.sessions.Delete(ctx, sid)
	}
	home := req.Scheme + "://" + req.Host + "/"
	if v := req.header("x-forwarded-proto"); v != "" {
		home = v + "://" + req.Host + "/"
	}
	return Response{
		Outcome:   Redirect,
		Status:    http.StatusFound,
		Reason:    "logged_out",
		Location:  p.oidc.LogoutURL(idToken, home),
		SetCookie: p.cfg.Cookie.Name + "=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
	}
}

func (p *Pipeline) cookie(id string, ttl time.Duration) string {
	parts := []string{
		fmt.Sprintf("%s=%s", p.cfg.Cookie.Name, id),
		"Path=/",
		"HttpOnly",
		"SameSite=Lax",
		fmt.Sprintf("Max-Age=%d", int(ttl.Seconds())),
	}
	if p.cfg.Cookie.Secure {
		parts = append(parts, "Secure")
	}
	return strings.Join(parts, "; ")
}

func redirectURI(req Request) string {
	scheme := req.Scheme
	if v := req.header("x-forwarded-proto"); v != "" {
		scheme = v
	}
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + req.Host + callbackPath
}

func bearerToken(req Request) string {
	v := req.header("authorization")
	if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
		return strings.TrimSpace(v[7:])
	}
	return ""
}

func cookieValue(header, name string) string {
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if k, v, ok := strings.Cut(part, "="); ok && k == name {
			return v
		}
	}
	return ""
}

func wantsHTML(req Request) bool {
	if req.Method != http.MethodGet {
		return false
	}
	accept := req.header("accept")
	return strings.Contains(accept, "text/html")
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func denyBody(reason, detail string) string {
	b, _ := json.Marshal(map[string]string{
		"error":  "access_denied",
		"reason": reason,
		"detail": detail,
	})
	return string(b)
}

func delegationBody(agent, capability, delegateURI string) string {
	b, _ := json.Marshal(map[string]string{
		"error":        "delegation_required",
		"reason":       logx.ReasonDelegationRequired,
		"detail":       fmt.Sprintf("%s holds no unexpired delegation for %s", agent, capability),
		"agent":        agent,
		"capability":   capability,
		"delegate_uri": delegateURI,
	})
	return string(b)
}

func consentBody(application, capability, consentURI string) string {
	b, _ := json.Marshal(map[string]string{
		"error":       "consent_required",
		"reason":      logx.ReasonConsentRequired,
		"detail":      fmt.Sprintf("%s has not been granted the %s capability", application, capability),
		"application": application,
		"capability":  capability,
		"consent_uri": consentURI,
	})
	return string(b)
}

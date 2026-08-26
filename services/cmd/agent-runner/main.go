// Command agent-runner is the agent.
//
// It is the smallest thing that is honestly an agent rather than a service with
// a fancy name: it receives a user's token, exchanges it for an identity of its
// own, decides at runtime which downstream calls a task needs, and makes them.
// It has no idea what it is allowed to do, and it does not ask — it tries, and
// reports what it was refused.
//
// The exchange is RFC 8693 (OAuth 2.0 Token Exchange), which Keycloak calls
// standard token exchange. The resulting token keeps `sub` = the human and sets
// `azp` = assistant-agent. That pair — the person who is accountable and the
// actor that is running — is the whole of agent identity, and everything
// downstream is built on being able to see both at once.
//
// Two things this deliberately does NOT do:
//
//   - it does not decide whether it may act. Every task below is attempted; the
//     authorizer at each callee refuses what was not delegated. An agent that
//     checked its own authority would be trusting the component most exposed to
//     prompt injection.
//   - it does not hold a long-lived credential for the user. The exchanged
//     token is minted per request and is scoped by whatever delegation exists
//     at the moment the call lands.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gerege/idp-mvp/internal/logx"
	"github.com/gerege/idp-mvp/internal/svc"
)

var (
	tokenURL     = svc.Env("TOKEN_URL", "http://keycloak.id.svc.cluster.local:8080/realms/gerege/protocol/openid-connect/token")
	clientID     = svc.Env("AGENT_CLIENT_ID", "assistant-agent")
	clientSecret = svc.Env("AGENT_CLIENT_SECRET", "assistant-agent-secret")
	homeID       = svc.Env("HOME_ID", "alice-home")

	deviceSvc  *svc.Upstream
	profileSvc *svc.Upstream
	httpClient = &http.Client{Timeout: 10 * time.Second}
)

// step is one thing the agent tried, and what came back.
type step struct {
	Action     string `json:"action"`
	Target     string `json:"target"`
	Capability string `json:"capability"`
	Status     int    `json:"status"`
	Reason     string `json:"reason,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Permitted  bool   `json:"permitted"`
}

type transcript struct {
	Task      string `json:"task"`
	Principal string `json:"principal"`
	Agent     string `json:"agent"`
	Exchanged bool   `json:"token_exchanged"`
	Steps     []step `json:"steps"`
	Error     string `json:"error,omitempty"`
}

func main() {
	deviceSvc = svc.NewUpstream(svc.Env("DEVICE_SERVICE_URL", "http://device-service.apps.svc.cluster.local"))
	profileSvc = svc.NewUpstream(svc.Env("PROFILE_SERVICE_URL", "http://profile-service.apps.svc.cluster.local"))

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/tasks/", runTask)
	svc.Run("agent-runner", svc.Env("ADDR", ":8080"), svc.Env("HEALTH_ADDR", ":8081"), mux)
}

func runTask(w http.ResponseWriter, r *http.Request) {
	task, _ := svc.PathTail(r.URL.Path, "/agent/tasks")
	if r.Method != http.MethodPost {
		svc.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	t := transcript{Task: task, Principal: r.Header.Get("x-user-id"), Agent: clientID}

	// The user's token arrives relayed by the authorizer in front of this
	// service. It is the subject token for the exchange, and it is the last
	// point at which this process holds the user's own credential.
	subject := bearer(r)
	if subject == "" {
		t.Error = "no subject token to act on"
		svc.WriteJSON(w, http.StatusBadRequest, t)
		return
	}

	agentToken, err := exchange(r.Context(), subject)
	if err != nil {
		// The audience gate. Keycloak refuses to mint an agent token from a
		// subject token that did not name this agent — so a token issued for
		// some other purpose cannot be repurposed into agent authority.
		t.Error = "token exchange refused: " + err.Error()
		logx.Error("token exchange failed", "err", err.Error(), "principal", t.Principal)
		svc.WriteJSON(w, http.StatusForbidden, t)
		return
	}
	t.Exchanged = true
	logx.Info("agent acting", "task", task, "principal", t.Principal, "agent", clientID)

	switch task {
	case "read-profile":
		t.Steps = append(t.Steps, t.call(r.Context(), agentToken, "read profile", "profile_read",
			profileSvc, http.MethodGet, "/api/profile/"+t.Principal, nil))

	case "check-home":
		t.Steps = append(t.Steps, t.call(r.Context(), agentToken, "list devices", "devices_view",
			deviceSvc, http.MethodGet, "/internal/homes/"+homeID+"/devices", nil))

	case "set-thermostat":
		t.Steps = append(t.Steps, t.call(r.Context(), agentToken, "set thermostat", "devices_control",
			deviceSvc, http.MethodPost, "/internal/devices/thermostat-1/state",
			[]byte(`{"state":"23°C"}`)))

	case "unlock-door":
		t.Steps = append(t.Steps, t.call(r.Context(), agentToken, "unlock lock-1", "devices_unlock",
			deviceSvc, http.MethodPost, "/internal/devices/lock-1/unlock", nil))

	case "everything":
		// What an agent left to its own devices actually does: try the lot.
		t.Steps = append(t.Steps,
			t.call(r.Context(), agentToken, "read profile", "profile_read",
				profileSvc, http.MethodGet, "/api/profile/"+t.Principal, nil),
			t.call(r.Context(), agentToken, "list devices", "devices_view",
				deviceSvc, http.MethodGet, "/internal/homes/"+homeID+"/devices", nil),
			t.call(r.Context(), agentToken, "set thermostat", "devices_control",
				deviceSvc, http.MethodPost, "/internal/devices/thermostat-1/state",
				[]byte(`{"state":"23°C"}`)),
			t.call(r.Context(), agentToken, "unlock lock-1", "devices_unlock",
				deviceSvc, http.MethodPost, "/internal/devices/lock-1/unlock", nil),
		)

	default:
		svc.WriteError(w, http.StatusNotFound, "unknown task: "+task)
		return
	}

	svc.WriteJSON(w, http.StatusOK, t)
}

// call attempts one downstream request with the agent's own token and records
// the outcome, refusals included. Nothing here inspects the result to decide
// whether to continue: the agent is not the judge of its own authority.
func (t *transcript) call(ctx context.Context, token, action, capability string,
	up *svc.Upstream, method, path string, body []byte) step {

	// io.Reader must stay a nil *interface*, not an interface holding a nil
	// pointer — the latter is non-nil to net/http, which then tries to read it.
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	s := step{Action: action, Target: path, Capability: capability}
	req, err := http.NewRequestWithContext(ctx, method, up.BaseURL+path, rdr)
	if err != nil {
		s.Reason = "request_error"
		s.Detail = err.Error()
		return s
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}

	resp, err := up.Client.Do(req)
	if err != nil {
		s.Reason = "transport_error"
		s.Detail = err.Error()
		return s
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)

	s.Status = resp.StatusCode
	s.Reason = resp.Header.Get("x-authz-reason")
	s.Permitted = resp.StatusCode >= 200 && resp.StatusCode < 300
	s.Detail = detailOf(buf[:n])
	logx.Info("agent step", "action", action, "capability", capability,
		"status", s.Status, "reason", s.Reason, "permitted", s.Permitted)
	return s
}

// exchange trades the user's token for the agent's own, per RFC 8693.
func exchange(ctx context.Context, subjectToken string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode exchange response (%d): %w", resp.StatusCode, err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("%s: %s", or(out.Error, "no token"), out.ErrorDesc)
	}
	return out.AccessToken, nil
}

func bearer(r *http.Request) string {
	v := r.Header.Get("authorization")
	if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
		return strings.TrimSpace(v[7:])
	}
	return ""
}

func detailOf(b []byte) string {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err == nil {
		if d, ok := m["detail"].(string); ok {
			return d
		}
	}
	s := strings.TrimSpace(string(b))
	if len(s) > 220 {
		s = s[:220] + "…"
	}
	return s
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

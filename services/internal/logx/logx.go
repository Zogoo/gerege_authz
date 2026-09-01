// Package logx emits the decision log and keeps a small in-memory ring of
// recent decisions for the demo.
//
// mvp_docs/04 §8: one structured record per decision, and no personal data —
// the principal is the opaque Keycloak subject identifier.
package logx

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Decision is one authorization outcome.
type Decision struct {
	Time       time.Time `json:"time"`
	DecisionID string    `json:"decision_id"`
	Enforcer   string    `json:"enforcer"`
	Principal  string    `json:"principal"`
	Kind       string    `json:"principal_kind"`
	// Actor is the agent acting for the principal, when there is one. It is
	// what makes an agent's action distinguishable from the human's in the
	// audit record — the single thing legacy IAM cannot express, because it has
	// one subject per token.
	Actor       string  `json:"actor,omitempty"`
	Application string  `json:"application"`
	Workload    string  `json:"workload"`
	Host        string  `json:"host"`
	Method      string  `json:"method"`
	Path        string  `json:"path"`
	Rule        string  `json:"rule"`
	Resource    string  `json:"resource"`
	Permission  string  `json:"permission"`
	Capability  string  `json:"capability"`
	ConsentSeen bool    `json:"consent_checked"`
	Delegated   bool    `json:"delegation_checked"`
	Allowed     bool    `json:"allowed"`
	Reason      string  `json:"reason"`
	LatencyMS   float64 `json:"latency_ms"`
}

// Reason codes (mvp_docs/04 §8). `conditional_result` and
// `workload_not_registered` are configuration errors wearing the costume of
// authorization failures; distinguishing them saves hours.
const (
	ReasonPermitted             = "permitted"
	ReasonNoSession             = "no_session"
	ReasonRedirectToLogin       = "redirect_to_login"
	ReasonTokenInvalid          = "token_invalid"
	ReasonNoRouteMatch          = "no_route_match"
	ReasonWorkloadNotRegistered = "workload_not_registered"
	ReasonPermissionDenied      = "permission_denied"
	ReasonConsentRequired       = "consent_required"
	ReasonDelegationRequired    = "delegation_required"
	ReasonAgentNotEnrolled      = "agent_not_enrolled"
	ReasonActorNotBound         = "actor_not_bound"
	ReasonStepUpRequired        = "step_up_required"
	ReasonConditionalResult     = "conditional_result"
	ReasonBackendUnavailable    = "backend_unavailable"
	ReasonUnknownApplication    = "unknown_application"
	ReasonInternalError         = "internal_error"
)

var (
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ringMu sync.Mutex
	ring   []Decision
)

const ringSize = 256

// Quiet silences the writer while keeping the ring buffer, for tests that
// assert on decisions rather than read them. The ring buffer is what
// TestAgentIsDistinguishableInTheAuditRecord inspects, so it must survive.
func Quiet() {
	logger = slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// Log writes the decision to stdout and records it in the ring buffer.
func Log(d Decision) {
	if d.Time.IsZero() {
		d.Time = time.Now().UTC()
	}
	logger.Info("authz.decision",
		"decision_id", d.DecisionID,
		"enforcer", d.Enforcer,
		"principal", d.Principal,
		"principal_kind", d.Kind,
		"actor", d.Actor,
		"application", d.Application,
		"workload", d.Workload,
		"host", d.Host,
		"method", d.Method,
		"path", d.Path,
		"rule", d.Rule,
		"resource", d.Resource,
		"permission", d.Permission,
		"capability", d.Capability,
		"consent_checked", d.ConsentSeen,
		"delegation_checked", d.Delegated,
		"allowed", d.Allowed,
		"reason", d.Reason,
		"latency_ms", d.LatencyMS,
	)
	ringMu.Lock()
	ring = append(ring, d)
	if len(ring) > ringSize {
		ring = ring[len(ring)-ringSize:]
	}
	ringMu.Unlock()
}

// Recent returns the buffered decisions, oldest first.
func Recent() []Decision {
	ringMu.Lock()
	defer ringMu.Unlock()
	out := make([]Decision, len(ring))
	copy(out, ring)
	return out
}

// RecentJSON renders the ring buffer for the debug endpoint.
func RecentJSON() ([]byte, error) { return json.MarshalIndent(Recent(), "", "  ") }

// Info logs an operational (non-decision) event.
func Info(msg string, args ...any) { logger.Info(msg, args...) }

// Error logs an operational failure.
func Error(msg string, args ...any) { logger.Error(msg, args...) }

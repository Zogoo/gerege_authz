package decision

import (
	"context"
	"testing"

	"github.com/gerege/idp-mvp/internal/logx"
	"github.com/gerege/idp-mvp/internal/spicedb"
)

// BenchmarkPipeline measures everything ext-authz does *except* talk to
// SpiceDB: JWT validation, route matching, identity extraction, response
// construction and the decision record. It answers whether the authorizer
// itself has headroom, or whether it is the thing that runs out first.
func BenchmarkPipeline(b *testing.B) {
	t := &testing.T{}
	env := newEnv(t)
	p := env.pipeline(fixedChecker{spicedb.Permitted, spicedb.Permitted})
	req := env.bearerReq("GET", "/api/profile/alice", env.token(t, "alice", "smarthome-app"))
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if got := p.Check(ctx, req); got.Outcome != Permit {
			b.Fatalf("unexpected outcome %v (%s)", got.Outcome, got.Reason)
		}
	}
}

// BenchmarkRouteMatch isolates route matching, which is linear over every rule
// and allocates a map of path parameters per request (mvp_docs/04 §4 accepted
// linear matching explicitly; this is the cost of that decision).
func BenchmarkRouteMatch(b *testing.B) {
	t := &testing.T{}
	env := newEnv(t)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, ok := env.snap.table.Match("profile-service.apps.svc.cluster.local",
			"GET", "/api/profile/alice"); !ok {
			b.Fatal("no match")
		}
	}
}

// BenchmarkTokenVerify isolates JWT signature validation, which happens once
// per hop — the same token, re-verified by every enforcement point on the path.
func BenchmarkTokenVerify(b *testing.B) {
	t := &testing.T{}
	env := newEnv(t)
	tok := env.token(t, "alice", "smarthome-app")
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := env.oidc.Verify(ctx, tok); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecisionLog isolates the decision record, which is written
// synchronously to stdout on the request path and appended to a
// mutex-protected ring buffer.
func BenchmarkDecisionLog(b *testing.B) {
	d := logx.Decision{
		DecisionID: "bench", Enforcer: "apps/profile-service", Principal: "alice",
		Kind: "user", Application: "smarthome-app", Host: "profile-service",
		Method: "GET", Path: "/api/profile/alice", Rule: "profile-read",
		Resource: "gerege/user_profile:alice", Permission: "view",
		Capability: "profile_read", ConsentSeen: true, Allowed: true, Reason: "permitted",
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		logx.Log(d)
	}
}

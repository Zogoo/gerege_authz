package spicedb

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestDelegationExpiresAgainstRealSpiceDB exercises the expiry path against a
// running SpiceDB, because expiry is enforced by the datastore and a fake would
// only test the fake.
//
//	SPICEDB_TEST_ENDPOINT=localhost:50051 go test ./internal/spicedb/
func TestDelegationExpiresAgainstRealSpiceDB(t *testing.T) {
	endpoint := os.Getenv("SPICEDB_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("set SPICEDB_TEST_ENDPOINT to run")
	}
	w, err := NewWriter(endpoint, envOr("SPICEDB_TEST_TOKEN", "gerege-mvp-key"), true, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	c, err := New(endpoint, envOr("SPICEDB_TEST_TOKEN", "gerege-mvp-key"), true, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx := context.Background()
	const user, agent, capability = "alice", "assistant", "devices_control"
	t.Cleanup(func() { _ = w.Undelegate(ctx, user, agent) })
	_ = w.Undelegate(ctx, user, agent)

	expires, err := w.Delegate(ctx, user, agent, []string{capability}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("delegated until %s (now %s)", expires.Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))

	check := func(when string) Outcome {
		out, err := c.CheckBulk(ctx, "test", true, Query{
			ResourceType: "gerege/delegation", ResourceID: DelegationID(user, agent),
			Permission: "includes", SubjectType: "gerege/capability", SubjectID: capability,
		})
		if err != nil {
			t.Fatalf("%s: %v", when, err)
		}
		t.Logf("%s → %s", when, out[0])
		return out[0]
	}

	if got := check("immediately"); got != Permitted {
		t.Fatalf("a fresh delegation was not honoured: %s", got)
	}

	// Read it back so the stored expiry is visible when this fails.
	dels, err := w.Delegations(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dels {
		for _, dc := range d.Capabilities {
			t.Logf("stored: %s/%s expires_at=%s", d.Agent, dc.Capability, dc.ExpiresAt.Format(time.RFC3339Nano))
			if dc.ExpiresAt.IsZero() {
				t.Errorf("%s was stored with no expiry — it is a standing grant", dc.Capability)
			}
		}
	}

	// Comfortably past the deadline: expiry is observed at the revision the
	// check is evaluated against, not at the instant the wall clock passes.
	time.Sleep(12 * time.Second)
	if got := check("after expiry"); got == Permitted {
		t.Fatal("an expired delegation was still honoured")
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

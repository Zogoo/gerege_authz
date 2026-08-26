package spicedb

import (
	"context"
	"os"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TestBulkVsSingleCheckOnExpiry compares the two check APIs against the same
// expired relationship, because the pipeline uses the bulk one and a difference
// between them would be an authorization bug rather than a curiosity.
func TestBulkVsSingleCheckOnExpiry(t *testing.T) {
	endpoint := os.Getenv("SPICEDB_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("set SPICEDB_TEST_ENDPOINT to run")
	}
	raw, err := authzed.NewClient(endpoint,
		grpcutil.WithInsecureBearerToken(envOr("SPICEDB_TEST_TOKEN", "gerege-mvp-key")),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	w, err := NewWriter(endpoint, envOr("SPICEDB_TEST_TOKEN", "gerege-mvp-key"), true, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	ctx := context.Background()
	const user, agent, capability = "alice", "assistant", "devices_control"
	t.Cleanup(func() { _ = w.Undelegate(ctx, user, agent) })
	_ = w.Undelegate(ctx, user, agent)

	if _, err := w.Delegate(ctx, user, agent, []string{capability}, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	time.Sleep(12 * time.Second)

	res := &v1.ObjectReference{ObjectType: "gerege/delegation", ObjectId: DelegationID(user, agent)}
	sub := &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: "gerege/capability", ObjectId: capability}}
	full := &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}}

	single, err := raw.CheckPermission(ctx, &v1.CheckPermissionRequest{
		Consistency: full, Resource: res, Permission: "includes", Subject: sub,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("CheckPermission        → %v", single.GetPermissionship())

	bulk, err := raw.CheckBulkPermissions(ctx, &v1.CheckBulkPermissionsRequest{
		Consistency: full,
		Items: []*v1.CheckBulkPermissionsRequestItem{
			{Resource: res, Permission: "includes", Subject: sub},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("CheckBulkPermissions   → %v", bulk.GetPairs()[0].GetItem().GetPermissionship())

	if single.GetPermissionship() != bulk.GetPairs()[0].GetItem().GetPermissionship() {
		t.Fatalf("the two check APIs disagree about an expired relationship: single=%v bulk=%v",
			single.GetPermissionship(), bulk.GetPairs()[0].GetItem().GetPermissionship())
	}
	if single.GetPermissionship() == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION {
		t.Fatal("an expired delegation was honoured")
	}
}

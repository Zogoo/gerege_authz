package spicedb

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TestConsistencyCost measures what the MVP's blanket `fully_consistent` costs
// against the alternatives, on the same server, with the same query.
//
// The MVP chose fully_consistent everywhere so that revocation is observable
// immediately and no assertion is timing-dependent (M-005). That is the right
// trade for a demonstration and the wrong one for throughput, because
// SpiceDB's caches are keyed by revision: a request pinned to the newest
// revision cannot reuse anything.
//
//	SPICEDB_TEST_ENDPOINT=localhost:50051 go test ./internal/spicedb/ -run ConsistencyCost -v
func TestConsistencyCost(t *testing.T) {
	endpoint := os.Getenv("SPICEDB_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("set SPICEDB_TEST_ENDPOINT to run")
	}
	c, err := authzed.NewClient(endpoint,
		grpcutil.WithInsecureBearerToken(envOr("SPICEDB_TEST_TOKEN", "gerege-mvp-key")),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx := context.Background()
	item := &v1.CheckBulkPermissionsRequestItem{
		Resource:   &v1.ObjectReference{ObjectType: "gerege/device", ObjectId: "lock-1"},
		Permission: "operate_lock",
		Subject: &v1.SubjectReference{
			Object: &v1.ObjectReference{ObjectType: "gerege/user", ObjectId: "alice"},
		},
	}

	// A ZedToken for at_least_as_fresh, obtained the way ext-authz obtains one.
	seed, err := c.CheckBulkPermissions(ctx, &v1.CheckBulkPermissionsRequest{
		Consistency: &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}},
		Items:       []*v1.CheckBulkPermissionsRequestItem{item},
	})
	if err != nil {
		t.Fatal(err)
	}
	tok := seed.GetCheckedAt()

	modes := []struct {
		name string
		cons *v1.Consistency
	}{
		{"fully_consistent   (what the MVP uses)",
			&v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}}},
		{"at_least_as_fresh  (ZedToken discipline)",
			&v1.Consistency{Requirement: &v1.Consistency_AtLeastAsFresh{AtLeastAsFresh: tok}}},
		{"minimize_latency   (excluded by mvp_docs/03 §6)",
			&v1.Consistency{Requirement: &v1.Consistency_MinimizeLatency{MinimizeLatency: true}}},
	}

	const (
		conc = 16
		iter = 300
	)
	for _, m := range modes {
		// warm
		for i := 0; i < 50; i++ {
			_, _ = c.CheckBulkPermissions(ctx, &v1.CheckBulkPermissionsRequest{
				Consistency: m.cons, Items: []*v1.CheckBulkPermissionsRequestItem{item}})
		}

		var mu sync.Mutex
		var lat []time.Duration
		var wg sync.WaitGroup
		start := time.Now()
		for w := 0; w < conc; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < iter; i++ {
					t0 := time.Now()
					_, err := c.CheckBulkPermissions(ctx, &v1.CheckBulkPermissionsRequest{
						Consistency: m.cons, Items: []*v1.CheckBulkPermissionsRequestItem{item}})
					d := time.Since(t0)
					if err != nil {
						continue
					}
					mu.Lock()
					lat = append(lat, d)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		elapsed := time.Since(start)

		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		p := func(q float64) time.Duration {
			if len(lat) == 0 {
				return 0
			}
			return lat[int(float64(len(lat)-1)*q)].Round(10 * time.Microsecond)
		}
		fmt.Printf("  %-44s checks/s=%7.0f  p50=%-10v p95=%-10v p99=%v\n",
			m.name, float64(len(lat))/elapsed.Seconds(), p(0.5), p(0.95), p(0.99))
	}
}

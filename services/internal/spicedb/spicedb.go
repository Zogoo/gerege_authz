// Package spicedb wraps the permission backend behind a narrow interface.
//
// M-005 requires this seam: the MVP does not cache authorization decisions, but
// "the SpiceDB client must sit behind an interface so caching can be added later
// without touching the decision pipeline."
//
// The client is deliberately read-only. mvp_docs/04 §1: a component that both
// decides and mutates authorization state is a component where a
// request-handling bug can escalate privilege. Relationship writes live in the
// account console, never on the request path.
package spicedb

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// Outcome is the result of one permission question.
type Outcome int

const (
	// Denied — no grant exists.
	Denied Outcome = iota
	// Permitted — a grant exists and is unconditional.
	Permitted
	// Conditional — a caveat is in play and the required context was not
	// supplied. M-008: this is treated as denied and logged as a configuration
	// error. Treating it as a permit would be a bypass that appears only when
	// context is missing, which is the case least likely to be tested.
	Conditional
)

func (o Outcome) String() string {
	switch o {
	case Permitted:
		return "permitted"
	case Conditional:
		return "conditional"
	default:
		return "denied"
	}
}

// Query is one check: does Subject have Permission on Resource?
type Query struct {
	ResourceType string
	ResourceID   string
	Permission   string
	SubjectType  string
	SubjectID    string
}

func (q Query) String() string {
	return fmt.Sprintf("%s:%s#%s@%s:%s", q.ResourceType, q.ResourceID, q.Permission, q.SubjectType, q.SubjectID)
}

// Checker is the seam. A caching implementation would satisfy this interface
// without the decision pipeline noticing.
type Checker interface {
	// CheckBulk answers every query in one round trip, preserving order.
	CheckBulk(ctx context.Context, requestID string, fullyConsistent bool, queries ...Query) ([]Outcome, error)
	Close() error
}

// Consistency modes, per mvp_docs/03 §6.
//
// `minimize_latency` is excluded from the MVP entirely: it would make
// assertion A8 — revoke, then observe the denial — flaky in a way that looks
// like a bug in the demo but is in fact the documented behaviour of the mode.
//
// `at_least_as_fresh` needs a ZedToken. ext-authz never writes, so it has no
// token of its own; instead it remembers the most recent `checked_at` returned
// by SpiceDB and offers that as the freshness floor. That gives monotonic
// freshness across the process lifetime without a write path. Before the first
// successful check there is no token, and the client falls back to
// `fully_consistent` rather than to something weaker.

// ErrBackendUnavailable is returned when SpiceDB could not be reached or could
// not answer. Every caller must turn this into a denial (claim C8).
var ErrBackendUnavailable = errors.New("spicedb unavailable")

type client struct {
	c       *authzed.Client
	timeout time.Duration

	mu       sync.RWMutex
	lastSeen string // most recent ZedToken observed
}

// New dials SpiceDB.
func New(endpoint, token string, plaintext bool, timeout time.Duration) (Checker, error) {
	opts := []grpc.DialOption{grpcutil.WithInsecureBearerToken(token)}
	if plaintext {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsOpt, err := grpcutil.WithSystemCerts(grpcutil.VerifyCA)
		if err != nil {
			return nil, err
		}
		opts = append(opts, tlsOpt)
	}
	c, err := authzed.NewClient(endpoint, opts...)
	if err != nil {
		return nil, err
	}
	return &client{c: c, timeout: timeout}, nil
}

func (c *client) Close() error { return c.c.Close() }

func (c *client) CheckBulk(ctx context.Context, requestID string, fullyConsistent bool, queries ...Query) ([]Outcome, error) {
	if len(queries) == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	// SpiceDB echoes X-Request-ID back on the response, which makes an
	// authorization decision traceable across ext-authz and SpiceDB logs
	// (mvp_docs/04 §2.3).
	ctx = metadata.AppendToOutgoingContext(ctx, "x-request-id", requestID)

	items := make([]*v1.CheckBulkPermissionsRequestItem, 0, len(queries))
	for _, q := range queries {
		items = append(items, &v1.CheckBulkPermissionsRequestItem{
			Resource:   &v1.ObjectReference{ObjectType: q.ResourceType, ObjectId: q.ResourceID},
			Permission: q.Permission,
			Subject: &v1.SubjectReference{
				Object: &v1.ObjectReference{ObjectType: q.SubjectType, ObjectId: q.SubjectID},
			},
		})
	}

	resp, err := c.c.CheckBulkPermissions(ctx, &v1.CheckBulkPermissionsRequest{
		Consistency: c.consistency(fullyConsistent),
		Items:       items,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBackendUnavailable, err)
	}
	c.observe(resp.GetCheckedAt())
	pairs := resp.GetPairs()
	if len(pairs) != len(queries) {
		return nil, fmt.Errorf("%w: expected %d results, got %d", ErrBackendUnavailable, len(queries), len(pairs))
	}

	out := make([]Outcome, len(pairs))
	for i, p := range pairs {
		if p.GetError() != nil {
			// A per-item error is still an inability to decide. Deny.
			return nil, fmt.Errorf("%w: item %d: %s", ErrBackendUnavailable, i, p.GetError().GetMessage())
		}
		switch p.GetItem().GetPermissionship() {
		case v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION:
			out[i] = Permitted
		case v1.CheckPermissionResponse_PERMISSIONSHIP_CONDITIONAL_PERMISSION:
			out[i] = Conditional
		default:
			out[i] = Denied
		}
	}
	return out, nil
}

func (c *client) observe(tok *v1.ZedToken) {
	if tok.GetToken() == "" {
		return
	}
	c.mu.Lock()
	c.lastSeen = tok.GetToken()
	c.mu.Unlock()
}

func (c *client) consistency(full bool) *v1.Consistency {
	if !full {
		c.mu.RLock()
		tok := c.lastSeen
		c.mu.RUnlock()
		if tok != "" {
			return &v1.Consistency{
				Requirement: &v1.Consistency_AtLeastAsFresh{
					AtLeastAsFresh: &v1.ZedToken{Token: tok},
				},
			}
		}
	}
	return &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}}
}

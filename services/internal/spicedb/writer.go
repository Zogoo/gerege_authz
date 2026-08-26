package spicedb

import (
	"context"
	"errors"
	"io"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Writer mutates consent relationships.
//
// It is deliberately a different type in a different process from Checker.
// mvp_docs/04 §1 keeps relationship writes off the request path: a component
// that both decides and mutates authorization state is a component where a
// request-handling bug can escalate privilege. Only the account console holds a
// Writer; ext-authz never does.
type Writer struct {
	c       *authzed.Client
	timeout time.Duration
}

// NewWriter dials SpiceDB for the consent write path.
func NewWriter(endpoint, token string, plaintext bool, timeout time.Duration) (*Writer, error) {
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
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Writer{c: c, timeout: timeout}, nil
}

func (w *Writer) Close() error { return w.c.Close() }

// Grant records one user's consent to one application for a set of
// capabilities. Granting writes one `granted` relationship per capability, plus
// the subject and grantee edges that make the grant revocable and attributable.
//
// TOUCH rather than CREATE: re-granting an existing capability must be
// idempotent, because a user clicking twice is not an error.
func (w *Writer) Grant(ctx context.Context, subject, application string, capabilities []string) error {
	if len(capabilities) == 0 {
		return errors.New("no capabilities selected")
	}
	grant := ConsentGrantID(subject, application)
	updates := []*v1.RelationshipUpdate{
		touch("gerege/consent_grant", grant, "subject", "gerege/user", subject),
		touch("gerege/consent_grant", grant, "grantee", "gerege/application", application),
	}
	for _, cap := range capabilities {
		updates = append(updates, touch("gerege/consent_grant", grant, "granted", "gerege/capability", cap))
	}
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	_, err := w.c.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{Updates: updates})
	return err
}

// Revoke deletes the grant.
//
// P4: revocation is deletion, and deny is the absence of a grant. There is no
// negative relationship to add and none to forget to remove — which is what
// keeps the model monotonic and revocation trivially correct.
func (w *Writer) Revoke(ctx context.Context, subject, application string, capabilities ...string) error {
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	grant := ConsentGrantID(subject, application)

	if len(capabilities) > 0 {
		updates := make([]*v1.RelationshipUpdate, 0, len(capabilities))
		for _, cap := range capabilities {
			updates = append(updates, del("gerege/consent_grant", grant, "granted", "gerege/capability", cap))
		}
		_, err := w.c.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{Updates: updates})
		return err
	}

	// Whole-grant revocation removes every edge, so nothing is left behind to
	// resurrect the grant by accident.
	_, err := w.c.DeleteRelationships(ctx, &v1.DeleteRelationshipsRequest{
		RelationshipFilter: &v1.RelationshipFilter{
			ResourceType:       "gerege/consent_grant",
			OptionalResourceId: grant,
		},
	})
	return err
}

// Grant describes what one application currently holds for one user.
type Grant struct {
	Application  string
	Capabilities []string
}

// Grants lists a user's live consent grants, newest state first read
// fully-consistently so that the account page never shows a grant the next
// request would refuse, or the reverse.
func (w *Writer) Grants(ctx context.Context, subject string) ([]Grant, error) {
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	stream, err := w.c.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
		Consistency: &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}},
		RelationshipFilter: &v1.RelationshipFilter{
			ResourceType:             "gerege/consent_grant",
			OptionalResourceIdPrefix: subject + "|",
			OptionalRelation:         "granted",
		},
	})
	if err != nil {
		return nil, err
	}
	byApp := map[string][]string{}
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		rel := msg.GetRelationship()
		app := applicationOf(rel.GetResource().GetObjectId())
		byApp[app] = append(byApp[app], rel.GetSubject().GetObject().GetObjectId())
	}
	out := make([]Grant, 0, len(byApp))
	for app, caps := range byApp {
		out = append(out, Grant{Application: app, Capabilities: caps})
	}
	return out, nil
}

// ConsentGrantID is the `<user>|<application>` object id.
//
// mvp_docs/03 writes this as `<user>~<application>`. SpiceDB object ids permit
// only [a-zA-Z0-9/_|\-=+] (spicedb pkg/tuple/parsing.go), so `~` cannot be
// used; `|` can, and carries the same meaning.
func ConsentGrantID(subject, application string) string { return subject + "|" + application }

func applicationOf(grantID string) string {
	for i := len(grantID) - 1; i >= 0; i-- {
		if grantID[i] == '|' {
			return grantID[i+1:]
		}
	}
	return grantID
}

func touch(resType, resID, relation, subType, subID string) *v1.RelationshipUpdate {
	return &v1.RelationshipUpdate{
		Operation:    v1.RelationshipUpdate_OPERATION_TOUCH,
		Relationship: relationship(resType, resID, relation, subType, subID),
	}
}

func del(resType, resID, relation, subType, subID string) *v1.RelationshipUpdate {
	return &v1.RelationshipUpdate{
		Operation:    v1.RelationshipUpdate_OPERATION_DELETE,
		Relationship: relationship(resType, resID, relation, subType, subID),
	}
}

func relationship(resType, resID, relation, subType, subID string) *v1.Relationship {
	return &v1.Relationship{
		Resource: &v1.ObjectReference{ObjectType: resType, ObjectId: resID},
		Relation: relation,
		Subject:  &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: subType, ObjectId: subID}},
	}
}

// Touch writes a single relationship, idempotently.
//
// Used by the assertion suite to demonstrate that authorization is data: adding
// one relationship changes the answer with no redeploy, no restart and no token
// reissue (assertion A5).
func (w *Writer) Touch(ctx context.Context, resType, resID, relation, subType, subID string) error {
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	_, err := w.c.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: []*v1.RelationshipUpdate{touch(resType, resID, relation, subType, subID)},
	})
	return err
}

// Delete removes a single relationship. Revocation is deletion (P4).
func (w *Writer) Delete(ctx context.Context, resType, resID, relation, subType, subID string) error {
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	_, err := w.c.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: []*v1.RelationshipUpdate{del(resType, resID, relation, subType, subID)},
	})
	return err
}

// ---------------------------------------------------------------------------
// delegation — a user's task-scoped, expiring grant to an agent
// ---------------------------------------------------------------------------

// DelegationID is the `<user>|<agent>` object id.
func DelegationID(subject, agent string) string { return subject + "|" + agent }

// Delegate grants an agent a set of capabilities on a user's behalf, for a
// bounded time.
//
// The TTL is not decoration. A delegation with no expiry is a standing
// privilege, which is the thing that makes agent access ungovernable: nobody
// remembers to remove it, and it survives whatever task motivated it. SpiceDB
// enforces the expiry itself, so a forgotten grant stops working without anyone
// having to notice.
func (w *Writer) Delegate(ctx context.Context, subject, agent string, capabilities []string, ttl time.Duration) (time.Time, error) {
	if len(capabilities) == 0 {
		return time.Time{}, errors.New("no capabilities selected")
	}
	if ttl <= 0 {
		return time.Time{}, errors.New("a delegation must expire")
	}
	expires := time.Now().Add(ttl).UTC()
	id := DelegationID(subject, agent)

	updates := []*v1.RelationshipUpdate{
		touch("gerege/delegation", id, "delegator", "gerege/user", subject),
		touch("gerege/delegation", id, "delegate", "gerege/agent", agent),
	}
	for _, capability := range capabilities {
		rel := relationship("gerege/delegation", id, "granted", "gerege/capability", capability)
		rel.OptionalExpiresAt = timestamppb.New(expires)
		updates = append(updates, &v1.RelationshipUpdate{
			Operation:    v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: rel,
		})
	}

	cctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	if _, err := w.c.WriteRelationships(cctx, &v1.WriteRelationshipsRequest{Updates: updates}); err != nil {
		return time.Time{}, err
	}
	return expires, nil
}

// Undelegate withdraws a delegation before it expires. Withdrawal is deletion,
// exactly as it is for consent and for permission (P4).
func (w *Writer) Undelegate(ctx context.Context, subject, agent string, capabilities ...string) error {
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	id := DelegationID(subject, agent)

	if len(capabilities) > 0 {
		updates := make([]*v1.RelationshipUpdate, 0, len(capabilities))
		for _, capability := range capabilities {
			updates = append(updates, del("gerege/delegation", id, "granted", "gerege/capability", capability))
		}
		_, err := w.c.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{Updates: updates})
		return err
	}
	_, err := w.c.DeleteRelationships(ctx, &v1.DeleteRelationshipsRequest{
		RelationshipFilter: &v1.RelationshipFilter{
			ResourceType:       "gerege/delegation",
			OptionalResourceId: id,
		},
	})
	return err
}

// Delegation is what one agent currently holds for one user.
type Delegation struct {
	Agent        string
	Capabilities []DelegatedCapability
}

// DelegatedCapability carries the expiry, so a person can see how long an
// agent's authority has left rather than having to trust that it ends.
type DelegatedCapability struct {
	Capability string
	ExpiresAt  time.Time
}

// Delegations lists a user's live delegations. Expired grants are already gone:
// SpiceDB does not return them, which is the point of using expiry rather than
// a timestamp the reader has to interpret.
func (w *Writer) Delegations(ctx context.Context, subject string) ([]Delegation, error) {
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	stream, err := w.c.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
		Consistency: &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}},
		RelationshipFilter: &v1.RelationshipFilter{
			ResourceType:             "gerege/delegation",
			OptionalResourceIdPrefix: subject + "|",
			OptionalRelation:         "granted",
		},
	})
	if err != nil {
		return nil, err
	}
	byAgent := map[string][]DelegatedCapability{}
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		rel := msg.GetRelationship()
		agent := applicationOf(rel.GetResource().GetObjectId())
		dc := DelegatedCapability{Capability: rel.GetSubject().GetObject().GetObjectId()}
		if ts := rel.GetOptionalExpiresAt(); ts != nil {
			dc.ExpiresAt = ts.AsTime()
		}
		byAgent[agent] = append(byAgent[agent], dc)
	}
	out := make([]Delegation, 0, len(byAgent))
	for agent, caps := range byAgent {
		out = append(out, Delegation{Agent: agent, Capabilities: caps})
	}
	return out, nil
}

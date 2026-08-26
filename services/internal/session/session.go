// Package session holds the server-side sessions that make browser SSO
// demonstrable (M-002).
//
// mvp_docs/04 §5: "Tokens never travel to the browser. The cookie is a
// reference; the tokens stay server-side."
//
// The MVP runs a single ext-authz replica, so the store is in memory. §5 lists
// this as an accepted option ("Redis, or in-memory for single-replica local
// runs"). Store is an interface so a Redis implementation can replace it
// without touching the pipeline; the failure semantics — a lookup error is a
// denial, never a permit — are the same either way.
package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// ErrNotFound means there is no live session for the identifier.
var ErrNotFound = errors.New("session not found")

// Session is everything ext-authz remembers about a logged-in browser.
type Session struct {
	ID string

	// Application is the OAuth client this session was established with.
	Application string

	// Pending-authentication fields. While Authenticated is false the session
	// exists only to bind the OIDC `state` to this browser.
	Authenticated bool
	State         string
	Nonce         string
	CodeVerifier  string
	ReturnTo      string

	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresAt    time.Time

	Subject     string
	DisplayName string

	CreatedAt time.Time
	ExpiresIn time.Time
}

// Store is the seam for session persistence.
type Store interface {
	New(ctx context.Context, s *Session, ttl time.Duration) error
	Get(ctx context.Context, id string) (*Session, error)
	Put(ctx context.Context, s *Session, ttl time.Duration) error
	Delete(ctx context.Context, id string) error
}

// NewID returns an opaque, unguessable session identifier.
func NewID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type memStore struct {
	mu   sync.RWMutex
	data map[string]*Session
}

// NewMemoryStore returns an in-process store with lazy expiry.
func NewMemoryStore() Store {
	m := &memStore{data: map[string]*Session{}}
	go m.reap()
	return m
}

func (m *memStore) reap() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		m.mu.Lock()
		for k, v := range m.data {
			if now.After(v.ExpiresIn) {
				delete(m.data, k)
			}
		}
		m.mu.Unlock()
	}
}

func (m *memStore) New(ctx context.Context, s *Session, ttl time.Duration) error {
	return m.Put(ctx, s, ttl)
}

func (m *memStore) Put(_ context.Context, s *Session, ttl time.Duration) error {
	cp := *s
	cp.ExpiresIn = time.Now().Add(ttl)
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	m.mu.Lock()
	m.data[cp.ID] = &cp
	m.mu.Unlock()
	return nil
}

func (m *memStore) Get(_ context.Context, id string) (*Session, error) {
	m.mu.RLock()
	s, ok := m.data[id]
	m.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	if time.Now().After(s.ExpiresIn) {
		m.mu.Lock()
		delete(m.data, id)
		m.mu.Unlock()
		return nil, ErrNotFound
	}
	cp := *s
	return &cp, nil
}

func (m *memStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	delete(m.data, id)
	m.mu.Unlock()
	return nil
}

// Package svc is the small amount of scaffolding every demonstration service
// shares: two listeners and one outbound helper.
package svc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gerege/idp-mvp/internal/logx"
)

// Run serves handler on addr and a liveness-only endpoint on healthAddr.
//
// mvp_docs/02 §5: Kubernetes probes originate on the node and cannot present
// mesh credentials, so the probe port is excluded from Envoy interception. That
// is the one documented exception to "every request is checked", and it stays
// safe only because the port serves liveness state and nothing else.
func Run(name, addr, healthAddr string, handler http.Handler) {
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
		mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ready")) })
		s := &http.Server{Addr: healthAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logx.Error("health listener stopped", "service", name, "err", err.Error())
		}
	}()

	srv := &http.Server{Addr: addr, Handler: logging(name, handler), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	logx.Info("service listening", "service", name, "addr", addr, "health", healthAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logx.Error("listener stopped", "service", name, "err", err.Error())
		os.Exit(1)
	}
}

func logging(name string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		logx.Info("request",
			"service", name, "method", r.Method, "path", r.URL.Path, "status", rec.status,
			"principal", r.Header.Get("x-user-id"), "application", r.Header.Get("x-application"),
			"decision_id", r.Header.Get("x-authz-decision-id"),
			"ms", float64(time.Since(start).Microseconds())/1000.0)
	})
}

type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(c int) { r.status = c; r.ResponseWriter.WriteHeader(c) }

// Upstream calls another service in the mesh.
//
// The caller's Authorization header is forwarded unchanged. That is what makes
// the internal hop carry the same principal and the same `azp`, so
// device-service can evaluate Alice's permission and Smart Home's consent for
// itself rather than trusting that smarthome-service already did
// (mvp_docs/02 §4.3). The mesh adds mTLS, which is where the *workload*
// identity on that hop comes from.
type Upstream struct {
	BaseURL string
	Client  *http.Client
}

// NewUpstream returns a client for a service base URL.
func NewUpstream(baseURL string) *Upstream {
	return &Upstream{BaseURL: strings.TrimRight(baseURL, "/"), Client: &http.Client{Timeout: 10 * time.Second}}
}

// Result is an upstream response, including denials, which are the interesting
// case: a 403 with a reason code is the demonstration.
type Result struct {
	Status int
	Body   []byte
	Reason string
	Header http.Header
}

// OK reports whether the upstream permitted and succeeded.
func (r Result) OK() bool { return r.Status >= 200 && r.Status < 300 }

// JSON decodes the body.
func (r Result) JSON(v any) error { return json.Unmarshal(r.Body, v) }

// Detail extracts the human-readable part of a denial body.
func (r Result) Detail() string {
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err == nil {
		if d, ok := m["detail"].(string); ok {
			return d
		}
		if d, ok := m["error"].(string); ok {
			return d
		}
	}
	s := strings.TrimSpace(string(r.Body))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// ConsentURI returns the challenge target when the denial was consent_required.
func (r Result) ConsentURI() string {
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err == nil {
		if u, ok := m["consent_uri"].(string); ok {
			return u
		}
	}
	return ""
}

// Do performs a request against the upstream, propagating the caller's identity.
func (u *Upstream) Do(ctx context.Context, from *http.Request, method, path string, body io.Reader) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, method, u.BaseURL+path, body)
	if err != nil {
		return Result{}, err
	}
	if from != nil {
		if v := from.Header.Get("authorization"); v != "" {
			req.Header.Set("authorization", v)
		}
		if v := from.Header.Get("x-request-id"); v != "" {
			req.Header.Set("x-request-id", v)
		}
	}
	req.Header.Set("accept", "application/json")
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	resp, err := u.Client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Result{}, err
	}
	return Result{Status: resp.StatusCode, Body: b, Reason: resp.Header.Get("x-authz-reason"), Header: resp.Header}, nil
}

// WriteJSON is the standard success response for the API services.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError is the standard failure response for the API services.
func WriteError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]string{"error": msg})
}

// Env reads a variable with a default.
func Env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// PathTail returns the path segment after prefix, up to the next slash.
func PathTail(path, prefix string) (string, string) {
	rest := strings.TrimPrefix(path, prefix)
	rest = strings.Trim(rest, "/")
	if rest == "" {
		return "", ""
	}
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

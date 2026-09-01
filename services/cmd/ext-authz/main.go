// Command ext-authz is the external authorizer: the only custom infrastructure
// component in the MVP, and the only place where a bug becomes an
// authorization failure.
//
// Three listeners, on three ports, for three different trust levels:
//
//	9001  gRPC  envoy.service.auth.v3.Authorization — called by every sidecar
//	9002  HTTP  /healthz, /readyz — liveness only, nothing else
//	9003  HTTP  /decisions — the decision-log ring buffer, for demos
//
// The health port is separate because Kubernetes probes originate on the node
// and cannot present mesh credentials (mvp_docs/02 §5). The rule that keeps
// that safe: the probe port exposes liveness state and nothing else. Port 9003
// is deliberately not published through a Service — reach it with
// `kubectl port-forward` when narrating a demo.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/gerege/idp-mvp/internal/config"
	"github.com/gerege/idp-mvp/internal/decision"
	"github.com/gerege/idp-mvp/internal/extauthz"
	"github.com/gerege/idp-mvp/internal/logx"
	"github.com/gerege/idp-mvp/internal/oidcauth"
	"github.com/gerege/idp-mvp/internal/session"
	"github.com/gerege/idp-mvp/internal/spicedb"
)

func main() {
	var (
		configPath  = flag.String("config", envOr("CONFIG_PATH", "/etc/ext-authz/config.yaml"), "path to the route configuration document")
		grpcAddr    = flag.String("grpc-addr", envOr("GRPC_ADDR", ":9001"), "ext_authz gRPC listen address")
		healthAddr  = flag.String("health-addr", envOr("HEALTH_ADDR", ":9002"), "health listen address (not mesh-intercepted)")
		debugAddr   = flag.String("debug-addr", envOr("DEBUG_ADDR", ":9003"), "decision-log listen address")
		consentBase = flag.String("consent-base", envOr("CONSENT_BASE_URL", "http://account.local.test"), "external base URL of the account console")
		reloadEvery = flag.Duration("reload-interval", 15*time.Second, "how often to re-read the route configuration")
	)
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		// mvp_docs/04 §6: a running authorizer with no rules is worse than one
		// that will not start.
		logx.Error("refusing to start: configuration is not usable", "err", err.Error())
		os.Exit(1)
	}
	snapshot, err := decision.NewSnapshot(cfg)
	if err != nil {
		logx.Error("refusing to start: route table is not usable", "err", err.Error())
		os.Exit(1)
	}

	// The health listener starts first, before anything that can block.
	//
	// Liveness and readiness answer different questions and must not be
	// conflated: the process is alive from here on, but it is not ready until
	// Keycloak has been reached and the gRPC listener is up. Starting the
	// health server after a blocking dependency check means the liveness probe
	// fails during the wait and the kubelet restarts the pod, forever.
	ready := &atomic.Bool{}
	go serveHealth(*healthAddr, ready)
	go serveDecisions(*debugAddr)

	hc := &http.Client{Timeout: 10 * time.Second}
	provider := oidcauth.New(cfg.Issuer, hc)

	// mvp_docs/06 hazard 4 costs more lost time than the rest combined, so it
	// is checked before serving a single request rather than discovered later
	// as "token validation fails for no apparent reason".
	if err := waitForIssuer(provider, 10*time.Minute); err != nil {
		logx.Error("refusing to start: Keycloak issuer check failed", "err", err.Error())
		os.Exit(1)
	}

	perms, err := spicedb.New(cfg.SpiceDB.Endpoint, cfg.SpiceDB.Token, cfg.SpiceDB.Insecure, cfg.SpiceDB.Timeout)
	if err != nil {
		logx.Error("refusing to start: cannot construct SpiceDB client", "err", err.Error())
		os.Exit(1)
	}
	defer perms.Close()

	pipeline := decision.New(snapshot, provider, session.NewMemoryStore(), perms, *consentBase)

	// Registries change when a device or an agent is onboarded. Reloading them
	// in place means enrolling a sensor does not require restarting the one
	// component every request in the mesh depends on.
	go watchConfig(*configPath, *reloadEvery, pipeline)

	grpcServer := grpc.NewServer()
	authv3.RegisterAuthorizationServer(grpcServer, extauthz.New(pipeline))
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcServer, hs)

	lis, err := net.Listen("tcp", *grpcAddr)
	if err != nil {
		logx.Error("cannot listen", "addr", *grpcAddr, "err", err.Error())
		os.Exit(1)
	}

	ready.Store(true)
	logx.Info("ext-authz ready",
		"grpc", *grpcAddr,
		"rules", len(cfg.Rules),
		"agents", len(cfg.Agents),
		"reload_interval", reloadEvery.String(),
		"applications", len(cfg.Applications),
		"issuer", cfg.Issuer.External,
		"spicedb", cfg.SpiceDB.Endpoint,
		"default_action", cfg.DefaultAction,
	)

	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		<-stop
		logx.Info("shutting down")
		grpcServer.GracefulStop()
	}()

	if err := grpcServer.Serve(lis); err != nil {
		logx.Error("grpc server stopped", "err", err.Error())
		os.Exit(1)
	}
}

// watchConfig re-reads the configuration and swaps it in when it changes.
//
// Two rules make this safe to run against a live authorizer:
//
//   - a configuration that fails to load or compile is *not* installed. The
//     previous one keeps serving. A bad edit must not be able to take the
//     authorizer down, and it must not be able to open it either.
//   - the swap is atomic and a request reads the snapshot once, so a reload
//     never applies halfway through a decision.
//
// Polling rather than inotify because a ConfigMap update replaces a symlink
// rather than writing the file, which is exactly the case filesystem watchers
// are worst at.
func watchConfig(path string, every time.Duration, p *decision.Pipeline) {
	last, err := fingerprint(path)
	if err != nil {
		logx.Error("cannot fingerprint config; reload disabled", "err", err.Error())
		return
	}
	for range time.Tick(every) {
		current, err := fingerprint(path)
		if err != nil || current == last {
			continue
		}
		cfg, err := config.Load(path)
		if err != nil {
			logx.Error("configuration changed but is not usable — keeping the previous one",
				"err", err.Error())
			last = current
			continue
		}
		snap, err := decision.NewSnapshot(cfg)
		if err != nil {
			logx.Error("route table changed but is not usable — keeping the previous one",
				"err", err.Error())
			last = current
			continue
		}
		p.Swap(snap)
		last = current
		logx.Info("configuration reloaded",
			"rules", snap.Rules(),
			"applications", len(cfg.Applications),
			"agents", len(cfg.Agents),
			"system_principals", len(cfg.SystemPrincipals))
	}
}

func fingerprint(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func waitForIssuer(p *oidcauth.Provider, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	var last error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := p.VerifyIssuer(ctx)
		cancel()
		if err == nil {
			return nil
		}
		last = err
		logx.Info("waiting for Keycloak", "err", err.Error())
		time.Sleep(3 * time.Second)
	}
	if last == nil {
		last = errors.New("timed out")
	}
	return last
}

func serveHealth(addr string, ready *atomic.Bool) {
	mux := http.NewServeMux()
	// Liveness state and nothing else. Any business logic reachable here would
	// be an authorization bypass — this port is not intercepted by Envoy,
	// precisely so that kubelet probes, which cannot present mesh credentials,
	// can reach it.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("starting"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logx.Error("health server stopped", "err", err.Error())
	}
}

func serveDecisions(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/decisions", func(w http.ResponseWriter, _ *http.Request) {
		b, err := logx.RecentJSON()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write(b)
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logx.Error("decision-log server stopped", "err", err.Error())
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

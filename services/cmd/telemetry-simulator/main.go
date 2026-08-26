// Command telemetry-simulator is the IoT device.
//
// It runs outside the mesh, exactly as a real device would: it obtains a token
// with the client-credentials grant, presents it at the ingress gateway, and is
// authorized on its own relationships. No user is involved at any point, and
// no consent is evaluated — mvp_docs/02 §4.4: requiring consent where no user
// is present would produce a record nobody granted and nobody can revoke.
//
// The interesting part of this program is what it does *wrong* on purpose.
// Every cycle it makes three requests: one it should be allowed (its own
// telemetry), one it should be refused (another device's telemetry), and one it
// should be refused (a user's profile). A device identity is not a skeleton key,
// and the log makes that visible without anyone having to take it on trust.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

type simulator struct {
	tokenURL     string
	gatewayAddr  string
	clientID     string
	clientSecret string
	deviceBase   string
	profileBase  string
	deviceID     string
	otherDevice  string
	client       *http.Client

	token     string
	tokenTill time.Time
}

func main() {
	s := &simulator{
		tokenURL:     env("TOKEN_URL", "http://id.local.test/realms/gerege/protocol/openid-connect/token"),
		clientID:     env("CLIENT_ID", "sensor-1"),
		clientSecret: env("CLIENT_SECRET", "sensor-1-secret"),
		deviceBase:   strings.TrimRight(env("DEVICE_URL", "http://device.local.test"), "/"),
		profileBase:  strings.TrimRight(env("PROFILE_URL", "http://profile.local.test"), "/"),
		deviceID:     env("DEVICE_ID", "sensor-1"),
		otherDevice:  env("OTHER_DEVICE_ID", "thermostat-1"),
		gatewayAddr:  env("GATEWAY_ADDR", ""),
	}
	// A device resolves the platform's hostnames to whatever address its network
	// hands back, and sends the hostname in the Host header. Inside the cluster
	// there is no DNS entry for id.local.test, so the dialer is pointed at the
	// gateway while the URLs — and therefore the Host headers, which is what
	// routing and the authorizer act on — stay exactly as a real device would
	// send them.
	tr := &http.Transport{DisableKeepAlives: true}
	if s.gatewayAddr != "" {
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, s.gatewayAddr)
		}
	}
	s.client = &http.Client{Timeout: 10 * time.Second, Transport: tr}
	interval, err := time.ParseDuration(env("INTERVAL", "15s"))
	if err != nil {
		interval = 15 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		<-stop
		cancel()
	}()

	logf("starting", "device=%s interval=%s ingress=%s gateway=%s",
		s.deviceID, interval, s.deviceBase, or(s.gatewayAddr, "system DNS"))
	t := time.NewTicker(interval)
	defer t.Stop()
	s.cycle(ctx)
	for {
		select {
		case <-ctx.Done():
			logf("stopping", "")
			return
		case <-t.C:
			s.cycle(ctx)
		}
	}
}

func (s *simulator) cycle(ctx context.Context) {
	tok, err := s.accessToken(ctx)
	if err != nil {
		logf("token", "FAILED %v", err)
		return
	}

	// 1. What the device is entitled to do: report its own readings.
	temp := 19 + rand.Float64()*6
	hum := 35 + rand.Float64()*25
	body, _ := json.Marshal(map[string]float64{
		"temperature": math.Round(temp*10) / 10,
		"humidity":    math.Round(hum*10) / 10,
	})
	status, reason, _ := s.post(ctx, s.deviceBase+"/telemetry/"+s.deviceID, tok, body)
	logf("telemetry/self", "%s status=%d reason=%s temperature=%.1f humidity=%.1f",
		verdict(status), status, orDash(reason), temp, hum)

	// 2. Another device's telemetry. sensor-1 has a `self` relationship to
	//    exactly one device, so this must be refused.
	status, reason, _ = s.post(ctx, s.deviceBase+"/telemetry/"+s.otherDevice, tok, body)
	logf("telemetry/other", "%s status=%d reason=%s device=%s (expected: denied)",
		verdict(status), status, orDash(reason), s.otherDevice)

	// 3. A user's profile. The device has no relationship to any user.
	status, reason, _ = s.get(ctx, s.profileBase+"/profile/alice", tok)
	logf("profile/alice", "%s status=%d reason=%s (expected: denied)",
		verdict(status), status, orDash(reason))

	// 4. The same telemetry with no credentials at all.
	status, reason, _ = s.post(ctx, s.deviceBase+"/telemetry/"+s.deviceID, "", body)
	logf("telemetry/anonymous", "%s status=%d reason=%s (expected: denied)",
		verdict(status), status, orDash(reason))
}

func (s *simulator) accessToken(ctx context.Context) (string, error) {
	if s.token != "" && time.Now().Before(s.tokenTill) {
		return s.token, nil
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", s.clientID)
	form.Set("client_secret", s.clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", err
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("no token (%d): %s %s", resp.StatusCode, tr.Error, tr.ErrorDesc)
	}
	s.token = tr.AccessToken
	s.tokenTill = time.Now().Add(time.Duration(tr.ExpiresIn-30) * time.Second)
	logf("token", "obtained via client_credentials, valid %ds", tr.ExpiresIn)
	return s.token, nil
}

func (s *simulator) post(ctx context.Context, url, token string, body []byte) (int, string, string) {
	return s.do(ctx, http.MethodPost, url, token, bytes.NewReader(body))
}

func (s *simulator) get(ctx context.Context, url, token string) (int, string, string) {
	return s.do(ctx, http.MethodGet, url, token, nil)
}

func (s *simulator) do(ctx context.Context, method, url, token string, body io.Reader) (int, string, string) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return 0, "request_error", err.Error()
	}
	req.Header.Set("accept", "application/json")
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	if token != "" {
		req.Header.Set("authorization", "Bearer "+token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, "transport_error", err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, resp.Header.Get("x-authz-reason"), string(b)
}

func verdict(status int) string {
	if status >= 200 && status < 300 {
		return "PERMITTED"
	}
	return "DENIED   "
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func logf(event, format string, args ...any) {
	fmt.Printf("%s  %-20s %s\n", time.Now().UTC().Format("15:04:05"), event, fmt.Sprintf(format, args...))
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

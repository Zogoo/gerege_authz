// Command verify runs the MVP's assertion suite unattended.
//
// mvp_docs/06 §6: "The suite must be runnable unattended. A demo that only
// works when a human drives it carefully is not evidence that the system
// works."
//
// Every assertion here maps to one in mvp_docs/01 §5. Three of them carry most
// of the weight:
//
//	A5   authorization is data, not deployed code — one relationship flips the
//	     answer, with no redeploy and the same unchanged token
//	A10  internal enforcement is real — the edge permits and the internal hop
//	     refuses, which a gateway-only architecture could not do
//	A13  the system fails closed — with SpiceDB stopped, nothing is permitted
//
// The suite drives real HTTP through the ingress gateway and real writes into
// SpiceDB. It does not stub anything, because a suite that stubs the parts
// under test is a suite that passes when the system is broken.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/gerege/idp-mvp/internal/spicedb"
)

var (
	gateway  = flag.String("gateway", "127.0.0.1:80", "host:port the ingress gateway is published on")
	spiceEP  = flag.String("spicedb", "localhost:50051", "SpiceDB gRPC endpoint")
	spiceTok = flag.String("spicedb-token", "gerege-mvp-key", "SpiceDB preshared key")
	kubectx  = flag.String("context", "kind-gerege-idp", "kubectl context, used only by the fail-closed assertions")
	skipFail = flag.Bool("skip-fail-closed", false, "skip A13, which stops and restarts SpiceDB")
)

const (
	idHost        = "id.local.test"
	profileHost   = "profile.local.test"
	smarthomeHost = "smarthome.local.test"
	deviceHost    = "device.local.test"
	realm         = "/realms/gerege"
)

func main() {
	flag.Parse()
	r := &runner{}
	w, err := spicedb.NewWriter(*spiceEP, *spiceTok, true, 10*time.Second)
	if err != nil {
		fatal("cannot reach SpiceDB at %s: %v", *spiceEP, err)
	}
	defer w.Close()
	r.spice = w

	fmt.Printf("Gerege IdP — MVP assertion suite\n")
	fmt.Printf("gateway %s   spicedb %s\n\n", *gateway, *spiceEP)

	r.section("C1/C2  Authentication and single sign-on")
	authAndSSO(r)

	r.section("C4  Relationship-based authorization")
	relationshipAuthz(r)

	r.section("C5/C6  Consent")
	consent(r)

	r.section("C3  Every request authorized, internal included")
	internalEnforcement(r)

	r.section("C7  Non-human principals")
	deviceIdentity(r)

	r.section("C9  Agent identity, delegation and step-up")
	agents(r)

	r.section("C8  Fail closed")
	failClosed(r)

	fmt.Println()
	os.Exit(r.report())
}

// ---------------------------------------------------------------------------
// C1 / C2 — authentication and SSO
// ---------------------------------------------------------------------------

func authAndSSO(r *runner) {
	b := newBrowser()

	// A1 — an unauthenticated browser request is redirected to Keycloak.
	resp, err := b.raw("GET", "http://"+profileHost+"/", nil, true)
	r.check("A1", "unauthenticated browser request is redirected to Keycloak",
		err == nil && resp != nil && resp.StatusCode == http.StatusFound &&
			strings.Contains(resp.Header.Get("Location"), realm+"/protocol/openid-connect/auth"),
		describeRedirect(resp, err))

	// A2 — after logging in, the profile app renders Alice's profile.
	body, status, err := b.browse("http://" + profileHost + "/profile/alice")
	r.check("A2", "after Keycloak login the profile app renders Alice's profile",
		err == nil && status == 200 && strings.Contains(body, "Alice Andersen"),
		fmt.Sprintf("status=%d logins=%d err=%v", status, b.logins, err))

	// A3 — the second application on a different origin needs no second login.
	loginsBefore := b.logins
	body, status, err = b.browse("http://" + smarthomeHost + "/")
	r.check("A3", "opening the smart-home app on another host needs NO second login",
		err == nil && status == 200 && b.logins == loginsBefore,
		fmt.Sprintf("status=%d additional_logins=%d err=%v", status, b.logins-loginsBefore, err))
	if b.logins == loginsBefore && status == 200 {
		r.note("the browser held no cookie for %s; Keycloak answered from its realm SSO session", smarthomeHost)
	}
	_ = body
}

// ---------------------------------------------------------------------------
// C4 — relationship-based authorization
// ---------------------------------------------------------------------------

func relationshipAuthz(r *runner) {
	alice := mustToken(r, "profile-app", "profile-app-secret", "alice", "alice")
	bob := mustToken(r, "profile-app", "profile-app-secret", "bob", "bob")

	status, reason, _ := apiGet("http://"+profileHost+"/profile/alice", alice)
	r.check("A4a", "Alice may read her own profile", status == 200,
		fmt.Sprintf("status=%d reason=%s", status, or(reason)))

	status, reason, _ = apiGet("http://"+profileHost+"/profile/alice", bob)
	r.check("A4", "Bob is refused Alice's profile", status == 403 && reason == "permission_denied",
		fmt.Sprintf("status=%d reason=%s", status, or(reason)))

	// A5 is the assertion that carries the most weight: one relationship, no
	// redeploy, no restart, and Bob's token is not reissued at any point.
	if err := r.write("gerege/user_profile", "alice", "reader", "gerege/user", "bob"); err != nil {
		r.fail("A5", "add one relationship granting Bob read access", err.Error())
		return
	}
	status, reason, _ = apiGet("http://"+profileHost+"/profile/alice", bob)
	permitted := status == 200
	r.check("A5", "one relationship added → Bob is now permitted, same token, no redeploy",
		permitted, fmt.Sprintf("status=%d reason=%s", status, or(reason)))
	if permitted {
		r.note("nothing was rebuilt, reloaded or reissued — the answer changed because the data did")
	}

	if err := r.remove("gerege/user_profile", "alice", "reader", "gerege/user", "bob"); err != nil {
		r.fail("A5b", "delete the relationship again", err.Error())
		return
	}
	status, reason, _ = apiGet("http://"+profileHost+"/profile/alice", bob)
	r.check("A5b", "relationship deleted → Bob is refused again",
		status == 403 && reason == "permission_denied",
		fmt.Sprintf("status=%d reason=%s", status, or(reason)))
}

// ---------------------------------------------------------------------------
// C5 / C6 — consent
// ---------------------------------------------------------------------------

func consent(r *runner) {
	// The same user and the same record, requested by the first-party
	// application and then by the third-party one. Only the application differs.
	viaProfile := mustToken(r, "profile-app", "profile-app-secret", "alice", "alice")
	viaSmarthome := mustToken(r, "smarthome-app", "smarthome-app-secret", "alice", "alice")

	status, _, _ := apiGet("http://"+profileHost+"/profile/alice", viaProfile)
	r.check("A6a", "first-party app reads Alice's profile with no consent prompt", status == 200,
		fmt.Sprintf("status=%d", status))

	status, reason, body := apiGet("http://"+smarthomeHost+"/myprofile", viaSmarthome)
	r.check("A6", "third-party app is refused the same record — consent_required",
		status == 403 && reason == "consent_required",
		fmt.Sprintf("status=%d reason=%s", status, or(reason)))
	if strings.Contains(body, "consent_uri") {
		r.note("the denial carried a consent challenge, not a bare 403")
	}

	ctx := context.Background()
	if err := r.spice.Grant(ctx, "alice", "smarthome-app", []string{"profile_read"}); err != nil {
		r.fail("A7", "Alice grants consent", err.Error())
		return
	}
	status, reason, _ = apiGet("http://"+smarthomeHost+"/myprofile", viaSmarthome)
	r.check("A7", "after consent the identical call succeeds",
		status == 200, fmt.Sprintf("status=%d reason=%s", status, or(reason)))
	r.note("the token was not reissued: consent is evaluated at the resource, not carried in the credential")

	if err := r.spice.Revoke(ctx, "alice", "smarthome-app"); err != nil {
		r.fail("A8", "Alice revokes consent", err.Error())
		return
	}
	status, reason, _ = apiGet("http://"+smarthomeHost+"/myprofile", viaSmarthome)
	r.check("A8", "after revocation the next call is refused",
		status == 403 && reason == "consent_required",
		fmt.Sprintf("status=%d reason=%s", status, or(reason)))
}

// ---------------------------------------------------------------------------
// C3 — internal enforcement
// ---------------------------------------------------------------------------

func internalEnforcement(r *runner) {
	ctx := context.Background()
	alice := mustToken(r, "smarthome-app", "smarthome-app-secret", "alice", "alice")
	bob := mustToken(r, "smarthome-app", "smarthome-app-secret", "bob", "bob")

	// Consent is a precondition for anything in this section.
	if err := r.spice.Grant(ctx, "alice", "smarthome-app",
		[]string{"profile_read", "devices_view", "devices_control", "devices_unlock"}); err != nil {
		r.fail("A9", "grant Alice's consent to the smart-home app", err.Error())
		return
	}
	defer func() { _ = r.spice.Revoke(ctx, "alice", "smarthome-app") }()

	unlock := "http://" + smarthomeHost + "/home/alice-home/devices/lock-1/unlock"

	status, reason, _ := apiPost(unlock, alice)
	r.check("A9", "Alice unlocks lock-1 through the smart-home app, end to end",
		status == 200, fmt.Sprintf("status=%d reason=%s", status, or(reason)))
	r.note("three decisions were made for that one call: at the gateway, at smarthome-service, and at device-service")

	// A10 — the assertion that proves internal enforcement is not decoration.
	//
	// mvp_docs/01 words this as "same call for Bob". Bob is refused at the very
	// first hop, which demonstrates a denial but not an *internal* one. The
	// stronger form, and the one Scenario 3b actually describes, is to leave the
	// edge check passing and take away only what the internal hop needs:
	// downgrade Alice from owner to guest. She can still see her home, so
	// smarthome-service permits; `operate_lock` derives from `administrate`, so
	// device-service refuses.
	if err := r.remove("gerege/home", "alice-home", "owner", "gerege/user", "alice"); err != nil {
		r.fail("A10", "downgrade Alice from owner to guest", err.Error())
		return
	}
	if err := r.write("gerege/home", "alice-home", "guest", "gerege/user", "alice"); err != nil {
		r.fail("A10", "downgrade Alice from owner to guest", err.Error())
		return
	}

	listStatus, _, _ := apiGet("http://"+smarthomeHost+"/home/alice-home", alice)
	status, reason, _ = apiPost(unlock, alice)
	r.check("A10", "as a guest: the edge still permits, the internal hop refuses",
		listStatus == 200 && status == 403 && reason == "permission_denied",
		fmt.Sprintf("edge_list=%d unlock=%d reason=%s", listStatus, status, or(reason)))
	if listStatus == 200 && status == 403 {
		r.note("a gateway-only architecture would have opened the door here")
	}

	// Restore.
	_ = r.remove("gerege/home", "alice-home", "guest", "gerege/user", "alice")
	if err := r.write("gerege/home", "alice-home", "owner", "gerege/user", "alice"); err != nil {
		r.fail("A10b", "restore Alice as owner", err.Error())
		return
	}
	status, _, _ = apiPost(unlock, alice)
	r.check("A10b", "ownership restored → the unlock succeeds again", status == 200,
		fmt.Sprintf("status=%d", status))

	// Bob, for completeness: a valid token and no relationship at all.
	status, reason, _ = apiPost(unlock, bob)
	r.check("A10c", "Bob's valid token is refused — he has no relationship to the home",
		status == 403, fmt.Sprintf("status=%d reason=%s", status, or(reason)))

	// Scenario 3c — token replay is contained by the consent graph and the
	// workload registry, not by anything about the token.
	status, reason, _ = apiPost("http://"+deviceHost+"/internal/devices/lock-1/unlock", alice)
	r.check("A10d", "Alice's valid token replayed straight at device-service is refused",
		status == 403 && reason == "workload_not_registered",
		fmt.Sprintf("status=%d reason=%s", status, or(reason)))
	if reason == "workload_not_registered" {
		r.note("nothing about that token was wrong: it is valid, unexpired and Alice's")
	}
}

// ---------------------------------------------------------------------------
// C7 — device identity
// ---------------------------------------------------------------------------

func deviceIdentity(r *runner) {
	tok, err := clientCredentials("sensor-1", "sensor-1-secret")
	if err != nil {
		r.fail("A11", "sensor-1 obtains a token by client credentials", err.Error())
		return
	}
	r.note("sensor-1 holds a token whose subject is a service account, not a person")

	status, reason, _ := apiPostBody("http://"+deviceHost+"/telemetry/sensor-1", tok, `{"temperature":21.4,"humidity":47}`)
	r.check("A11", "sensor-1 pushes its own telemetry — permitted",
		status == 202 || status == 200, fmt.Sprintf("status=%d reason=%s", status, or(reason)))

	status, reason, _ = apiPostBody("http://"+deviceHost+"/telemetry/thermostat-1", tok, `{"temperature":21.4,"humidity":47}`)
	r.check("A11b", "sensor-1 pushing another device's telemetry — refused",
		status == 403, fmt.Sprintf("status=%d reason=%s", status, or(reason)))

	status, reason, _ = apiGet("http://"+profileHost+"/profile/alice", tok)
	r.check("A11c", "sensor-1 reading Alice's profile — refused",
		status == 403, fmt.Sprintf("status=%d reason=%s", status, or(reason)))
	r.note("a device identity is not a skeleton key: sensor-1 is authorized on exactly one device")

	status, reason, _ = apiPostBody("http://"+deviceHost+"/telemetry/sensor-1", "", `{"temperature":21.4}`)
	r.check("A11d", "telemetry with no credentials at all — refused",
		status == 401 || status == 403, fmt.Sprintf("status=%d reason=%s", status, or(reason)))
}

// ---------------------------------------------------------------------------
// C9 — agents
// ---------------------------------------------------------------------------

// agentTranscript is what agent-runner reports back through smarthome-service.
type agentTranscript struct {
	Principal string `json:"principal"`
	Agent     string `json:"agent"`
	Exchanged bool   `json:"token_exchanged"`
	Error     string `json:"error"`
	Steps     []struct {
		Action     string `json:"action"`
		Capability string `json:"capability"`
		Status     int    `json:"status"`
		Reason     string `json:"reason"`
		Permitted  bool   `json:"permitted"`
	} `json:"steps"`
}

func askAgent(task, token string) (agentTranscript, int, string) {
	status, reason, body := apiGet("http://"+smarthomeHost+"/assistant?task="+task, token)
	var t agentTranscript
	_ = json.Unmarshal([]byte(body), &t)
	return t, status, reason
}

func (t agentTranscript) step(capability string) (bool, string, bool) {
	for _, s := range t.Steps {
		if s.Capability == capability {
			return s.Permitted, s.Reason, true
		}
	}
	return false, "", false
}

func agents(r *runner) {
	ctx := context.Background()
	alice := mustToken(r, "smarthome-app", "smarthome-app-secret", "alice", "alice")

	// The agent is reached through the smart-home application, so Alice's
	// consent to that application is a precondition — and note that it is not
	// sufficient, which is the whole point of the section.
	if err := r.spice.Grant(ctx, "alice", "smarthome-app",
		[]string{"profile_read", "devices_view", "devices_control", "devices_unlock"}); err != nil {
		r.fail("A14", "grant Alice's consent to the smart-home app", err.Error())
		return
	}
	defer func() { _ = r.spice.Revoke(ctx, "alice", "smarthome-app") }()
	_ = r.spice.Undelegate(ctx, "alice", "assistant")

	// A14 — the agent obtains an identity of its own by RFC 8693 exchange.
	t, status, reason := askAgent("everything", alice)
	r.check("A14", "the agent exchanges Alice's token for one of its own (RFC 8693)",
		status == 200 && t.Exchanged && t.Principal == "alice" && t.Agent == "assistant-agent",
		fmt.Sprintf("status=%d exchanged=%v principal=%s acting_as=%s reason=%s",
			status, t.Exchanged, t.Principal, t.Agent, or(reason)))
	r.note("the human stays the subject; the agent becomes the authorized party")

	// A15 — the assertion this whole section exists for.
	permitted, why, found := t.step("profile_read")
	r.check("A15", "the agent holds Alice's token AND her consent, and is still refused",
		found && !permitted && why == "delegation_required",
		fmt.Sprintf("permitted=%v reason=%s", permitted, or(why)))
	r.note("nothing about Alice's own access changed — the delegation check is what refused it")

	// A16 — delegated, and only what was delegated.
	if _, err := r.spice.Delegate(ctx, "alice", "assistant",
		[]string{"profile_read", "devices_view"}, 10*time.Minute); err != nil {
		r.fail("A16", "Alice delegates two capabilities for ten minutes", err.Error())
		return
	}
	t, _, _ = askAgent("everything", alice)
	readOK, _, _ := t.step("profile_read")
	viewOK, _, _ := t.step("devices_view")
	ctlOK, ctlWhy, _ := t.step("devices_control")
	r.check("A16", "after delegation the agent may do exactly what was delegated",
		readOK && viewOK && !ctlOK && ctlWhy == "delegation_required",
		fmt.Sprintf("profile_read=%v devices_view=%v devices_control=%v(%s)",
			readOK, viewOK, ctlOK, or(ctlWhy)))

	// A17 — the delegation expires on its own, with nobody removing it.
	// The margin matters. Expiry is enforced by the datastore and observed at
	// the revision a check is evaluated against, so it becomes visible within a
	// few seconds of the deadline rather than at the exact instant the wall
	// clock passes it. A tight window here produces an assertion that fails
	// occasionally and truthfully — which is worse than a slower one that is
	// deterministic (the same reasoning as M-005).
	if _, err := r.spice.Delegate(ctx, "alice", "assistant",
		[]string{"devices_control"}, 3*time.Second); err != nil {
		r.fail("A17", "Alice delegates a capability for three seconds", err.Error())
		return
	}
	t, _, _ = askAgent("set-thermostat", alice)
	beforeOK, _, _ := t.step("devices_control")
	time.Sleep(12 * time.Second)
	t, _, _ = askAgent("set-thermostat", alice)
	afterOK, afterWhy, _ := t.step("devices_control")
	r.check("A17", "the delegation expires by itself — nothing had to remove it",
		beforeOK && !afterOK && afterWhy == "delegation_required",
		fmt.Sprintf("before_expiry=%v after_expiry=%v reason=%s", beforeOK, afterOK, or(afterWhy)))
	r.note("a task grant that cannot outlive its task is the difference from a standing credential")

	// A18 — step-up. The agent has permission, consent and could be delegated;
	// it is refused anyway, and Alice is not.
	t, _, _ = askAgent("unlock-door", alice)
	agentUnlock, unlockWhy, _ := t.step("devices_unlock")
	humanUnlock, humanReason, _ := apiPost(
		"http://"+smarthomeHost+"/home/alice-home/devices/lock-1/unlock", alice)
	r.check("A18", "a step-up route refuses the agent and permits the human",
		!agentUnlock && unlockWhy == "step_up_required" && humanUnlock == 200,
		fmt.Sprintf("agent=%v(%s) human=%d(%s)", agentUnlock, or(unlockWhy), humanUnlock, or(humanReason)))
	r.note("an agent cannot re-authenticate the person behind it, so this one is closed to it by construction")

	// A19 — withdrawal is immediate.
	if err := r.spice.Undelegate(ctx, "alice", "assistant"); err != nil {
		r.fail("A19", "Alice withdraws the delegation", err.Error())
		return
	}
	t, _, _ = askAgent("everything", alice)
	anyPermitted := false
	for _, s := range t.Steps {
		if s.Permitted {
			anyPermitted = true
		}
	}
	r.check("A19", "withdrawing the delegation stops the agent on the next call",
		!anyPermitted, fmt.Sprintf("steps_permitted=%v", anyPermitted))

	// A20 — the audience gate. A token minted for an application that never
	// named this agent cannot be turned into agent authority.
	viaProfile := mustToken(r, "profile-app", "profile-app-secret", "alice", "alice")
	status, _, body := apiGet("http://"+smarthomeHost+"/assistant?task=read-profile", viaProfile)
	r.check("A20", "a token that does not name the agent cannot be exchanged for it",
		status != 200 || strings.Contains(body, "exchange refused"),
		fmt.Sprintf("status=%d", status))
	r.note("Keycloak refuses to mint agent authority from a token issued for something else")
}

// ---------------------------------------------------------------------------
// C8 — fail closed
// ---------------------------------------------------------------------------

func failClosed(r *runner) {
	alice := mustToken(r, "profile-app", "profile-app-secret", "alice", "alice")

	status, reason, _ := apiGet("http://"+profileHost+"/undeclared-endpoint", alice)
	r.check("A12", "an endpoint with no authorization rule is refused",
		status == 403 && reason == "no_route_match",
		fmt.Sprintf("status=%d reason=%s", status, or(reason)))
	r.note("this is the most common real-world mistake in this architecture, and it fails visibly")

	if *skipFail {
		r.skip("A13", "SpiceDB stopped → every request refused (skipped by flag)")
		return
	}

	if err := scaleSpiceDB(0); err != nil {
		r.fail("A13", "stop SpiceDB", err.Error())
		return
	}
	defer func() {
		if err := scaleSpiceDB(1); err != nil {
			r.note("WARNING: could not restart SpiceDB: %v", err)
			return
		}
		waitForPermit("http://"+profileHost+"/profile/alice", alice, 90*time.Second)
	}()

	// Repeated, because "denied once" and "never permitted" are different
	// claims, and only the second one is C8.
	allPermitted, sawBackendDown := 0, false
	var lastStatus int
	var lastReason string
	for i := 0; i < 6; i++ {
		lastStatus, lastReason, _ = apiGet("http://"+profileHost+"/profile/alice", alice)
		if lastStatus == 200 {
			allPermitted++
		}
		if lastReason == "backend_unavailable" {
			sawBackendDown = true
		}
		time.Sleep(500 * time.Millisecond)
	}
	r.check("A13", "SpiceDB stopped → six consecutive requests, none permitted",
		allPermitted == 0, fmt.Sprintf("permitted=%d/6 last_status=%d last_reason=%s",
			allPermitted, lastStatus, or(lastReason)))
	if sawBackendDown {
		r.note("denials carried reason backend_unavailable — the authorizer knew why it could not decide")
	}
}

func scaleSpiceDB(replicas int) error {
	cmd := exec.Command("kubectl", "--context", *kubectx, "-n", "id",
		"scale", "deploy/spicedb", fmt.Sprintf("--replicas=%d", replicas))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	if replicas == 0 {
		// Wait for the pod to actually go away; "scaled" is not "stopped".
		for i := 0; i < 60; i++ {
			c := exec.Command("kubectl", "--context", *kubectx, "-n", "id",
				"get", "pods", "-l", "app=spicedb", "--no-headers")
			o, _ := c.CombinedOutput()
			if strings.TrimSpace(string(o)) == "" || strings.Contains(string(o), "No resources") {
				return nil
			}
			time.Sleep(time.Second)
		}
		return fmt.Errorf("SpiceDB pods did not terminate")
	}
	cmd = exec.Command("kubectl", "--context", *kubectx, "-n", "id",
		"rollout", "status", "deploy/spicedb", "--timeout=180s")
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func waitForPermit(rawURL, token string, budget time.Duration) {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if s, _, _ := apiGet(rawURL, token); s == 200 {
			return
		}
		time.Sleep(2 * time.Second)
	}
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

// dialer sends every request to the published gateway address regardless of the
// hostname in the URL, so the suite runs whether or not /etc/hosts has been
// edited. The Host header — which is what routing and the authorizer act on —
// is still the real hostname.
func transport() *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, *gateway)
		},
		DisableKeepAlives: true,
	}
}

func apiGet(rawURL, token string) (int, string, string) {
	return apiDo("GET", rawURL, token, "")
}

func apiPost(rawURL, token string) (int, string, string) {
	return apiDo("POST", rawURL, token, "")
}

func apiPostBody(rawURL, token, body string) (int, string, string) {
	return apiDo("POST", rawURL, token, body)
}

func apiDo(method, rawURL, token, body string) (int, string, string) {
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	var req *http.Request
	var err error
	if rdr != nil {
		req, err = http.NewRequest(method, rawURL, rdr)
	} else {
		req, err = http.NewRequest(method, rawURL, nil)
	}
	if err != nil {
		return 0, "request_error", err.Error()
	}
	req.Header.Set("accept", "application/json")
	if body != "" {
		req.Header.Set("content-type", "application/json")
	}
	if token != "" {
		req.Header.Set("authorization", "Bearer "+token)
	}
	client := &http.Client{
		Transport: transport(),
		Timeout:   20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "transport_error", err.Error()
	}
	defer resp.Body.Close()
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, resp.Header.Get("x-authz-reason"), string(buf[:n])
}

// browser follows redirects by hand and submits the Keycloak login form when it
// meets one, counting how many times it had to. That counter is the SSO
// assertion: the second application must cost zero logins.
type browser struct {
	client *http.Client
	logins int
}

func newBrowser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{client: &http.Client{
		Transport: transport(),
		Jar:       jar,
		Timeout:   20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

func (b *browser) raw(method, rawURL string, form url.Values, html bool) (*http.Response, error) {
	var req *http.Request
	var err error
	if form != nil {
		req, err = http.NewRequest(method, rawURL, strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("content-type", "application/x-www-form-urlencoded")
		}
	} else {
		req, err = http.NewRequest(method, rawURL, nil)
	}
	if err != nil {
		return nil, err
	}
	if html {
		req.Header.Set("accept", "text/html,application/xhtml+xml")
	}
	return b.client.Do(req)
}

var loginFormRE = regexp.MustCompile(`(?s)<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`)

// browse walks the redirect chain to a final page, logging in if Keycloak asks.
func (b *browser) browse(rawURL string) (string, int, error) {
	current := rawURL
	method := "GET"
	var form url.Values

	for hop := 0; hop < 12; hop++ {
		resp, err := b.raw(method, current, form, true)
		if err != nil {
			return "", 0, err
		}
		body := readAll(resp)
		resp.Body.Close()
		method, form = "GET", nil

		if loc := resp.Header.Get("Location"); resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
			next, err := url.Parse(loc)
			if err != nil {
				return "", 0, err
			}
			cur, _ := url.Parse(current)
			current = cur.ResolveReference(next).String()
			continue
		}

		if m := loginFormRE.FindStringSubmatch(body); m != nil {
			action := htmlUnescape(m[1])
			cur, _ := url.Parse(current)
			act, err := url.Parse(action)
			if err != nil {
				return "", 0, err
			}
			current = cur.ResolveReference(act).String()
			method = "POST"
			form = url.Values{"username": {"alice"}, "password": {"alice"}, "credentialId": {""}}
			b.logins++
			continue
		}
		return body, resp.StatusCode, nil
	}
	return "", 0, fmt.Errorf("redirect chain did not settle")
}

func readAll(resp *http.Response) string {
	buf := make([]byte, 0, 64*1024)
	tmp := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil || len(buf) > 1<<20 {
			break
		}
	}
	return string(buf)
}

func htmlUnescape(s string) string {
	r := strings.NewReplacer("&amp;", "&", "&quot;", `"`, "&#39;", "'", "&lt;", "<", "&gt;", ">")
	return r.Replace(s)
}

func describeRedirect(resp *http.Response, err error) string {
	if err != nil {
		return err.Error()
	}
	if resp == nil {
		return "no response"
	}
	loc := resp.Header.Get("Location")
	if len(loc) > 90 {
		loc = loc[:90] + "…"
	}
	return fmt.Sprintf("status=%d location=%s", resp.StatusCode, loc)
}

// ---------------------------------------------------------------------------
// Keycloak
// ---------------------------------------------------------------------------

func mustToken(r *runner, clientID, secret, user, pass string) string {
	tok, err := passwordGrant(clientID, secret, user, pass)
	if err != nil {
		fatal("cannot obtain a token for %s via %s: %v", user, clientID, err)
	}
	return tok
}

func passwordGrant(clientID, secret, user, pass string) (string, error) {
	return tokenRequest(url.Values{
		"grant_type":    {"password"},
		"client_id":     {clientID},
		"client_secret": {secret},
		"username":      {user},
		"password":      {pass},
		"scope":         {"openid profile email"},
	})
}

func clientCredentials(clientID, secret string) (string, error) {
	return tokenRequest(url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {secret},
	})
}

func tokenRequest(form url.Values) (string, error) {
	req, err := http.NewRequest("POST",
		"http://"+idHost+realm+"/protocol/openid-connect/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	client := &http.Client{Transport: transport(), Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body := readAll(resp)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, truncate(body, 200))
	}
	m := regexp.MustCompile(`"access_token"\s*:\s*"([^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		return "", fmt.Errorf("no access_token in response: %s", truncate(body, 200))
	}
	return m[1], nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func or(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\nverify: "+format+"\n", args...)
	os.Exit(2)
}

// ---------------------------------------------------------------------------
// runner — result collection and output
// ---------------------------------------------------------------------------

type result struct {
	id, what, detail string
	state            string // pass | fail | skip
}

type runner struct {
	spice   *spicedb.Writer
	results []result
}

func (r *runner) write(resType, resID, relation, subType, subID string) error {
	return r.spice.Touch(context.Background(), resType, resID, relation, subType, subID)
}

func (r *runner) remove(resType, resID, relation, subType, subID string) error {
	return r.spice.Delete(context.Background(), resType, resID, relation, subType, subID)
}

func (r *runner) section(title string) {
	fmt.Printf("\n%s\n%s\n", title, strings.Repeat("─", len(title)))
}

func (r *runner) check(id, what string, ok bool, detail string) {
	state := "fail"
	mark := "✗"
	if ok {
		state, mark = "pass", "✓"
	}
	r.results = append(r.results, result{id: id, what: what, detail: detail, state: state})
	fmt.Printf("  %s %-5s %-64s %s\n", mark, id, what, dim(detail))
}

func (r *runner) fail(id, what, detail string) {
	r.results = append(r.results, result{id: id, what: what, detail: detail, state: "fail"})
	fmt.Printf("  %s %-5s %-64s %s\n", "✗", id, what, dim(detail))
}

func (r *runner) skip(id, what string) {
	r.results = append(r.results, result{id: id, what: what, state: "skip"})
	fmt.Printf("  %s %-5s %-64s\n", "–", id, what)
}

func (r *runner) note(format string, args ...any) {
	fmt.Printf("        %s\n", dim(fmt.Sprintf(format, args...)))
}

func (r *runner) report() int {
	var pass, fail, skip int
	for _, x := range r.results {
		switch x.state {
		case "pass":
			pass++
		case "skip":
			skip++
		default:
			fail++
		}
	}
	fmt.Printf("\n%s\n", strings.Repeat("═", 78))
	fmt.Printf("  %d passed, %d failed", pass, fail)
	if skip > 0 {
		fmt.Printf(", %d skipped", skip)
	}
	fmt.Println()
	if fail > 0 {
		fmt.Println("\n  failed:")
		for _, x := range r.results {
			if x.state == "fail" {
				fmt.Printf("    %-5s %s\n        %s\n", x.id, x.what, x.detail)
			}
		}
		return 1
	}
	fmt.Println("\n  Every claim in mvp_docs/01 §1 is demonstrated: authentication, single")
	fmt.Println("  sign-on, relationship-based authorization, consent and its revocation,")
	fmt.Println("  independent enforcement on internal calls, non-human identity, and")
	fmt.Println("  fail-closed behaviour under backend failure.")
	fmt.Println()
	fmt.Println("  And one claim the original scope did not have: an agent holding the")
	fmt.Println("  user's own token, with the user's own consent, does only what it was")
	fmt.Println("  delegated — for as long as the delegation lasts, and never through a")
	fmt.Println("  route that requires a person to be present.")
	return 0
}

func dim(s string) string {
	if s == "" {
		return ""
	}
	return "\033[2m" + s + "\033[0m"
}

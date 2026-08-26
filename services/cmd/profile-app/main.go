// Command profile-app is the browser-facing first-party application.
//
// It is where Scenario 1 starts: an unauthenticated visit is redirected to
// Keycloak by the authorizer sitting in front of this process, and comes back
// with a session. The app itself never sees a login form, a token, or a
// password — it receives a request that has already been authorized and a
// header telling it who the user is.
//
// It is also half of the Scenario 3a contrast: this application is configured
// first-party, so reading Alice's own profile needs no consent. The smart-home
// application asks for exactly the same data and is refused until she grants it.
package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gerege/idp-mvp/internal/svc"
	"github.com/gerege/idp-mvp/internal/webui"
)

var (
	profileSvc *svc.Upstream
	smarthome  = svc.Env("SMARTHOME_URL", "http://smarthome.local.test")
	account    = svc.Env("ACCOUNT_URL", "http://account.local.test")
)

type profile struct {
	UserID  string `json:"userId"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Phone   string `json:"phone"`
	Address string `json:"address"`
}

func main() {
	profileSvc = svc.NewUpstream(svc.Env("PROFILE_SERVICE_URL", "http://profile-service.apps.svc.cluster.local"))
	mux := http.NewServeMux()
	mux.HandleFunc("/", home)
	mux.HandleFunc("/profile/", viewProfile)
	mux.HandleFunc("/static/", static)
	svc.Run("profile-app", svc.Env("ADDR", ":8080"), svc.Env("HEALTH_ADDR", ":8081"), mux)
}

func home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	id := webui.From(r)
	body := webui.Card("Profiles", fmt.Sprintf(`<table>
<tr><th>Profile</th><th>Owner</th><th></th></tr>
<tr><td>Alice's profile</td><td>alice</td><td><a class="btn" href="/profile/alice">Open</a></td></tr>
<tr><td>Bob's profile</td><td>bob</td><td><a class="btn" href="/profile/bob">Open</a></td></tr>
</table><p class="note">You are signed in as <strong>%s</strong>. Opening a profile you have no
relationship to returns a denial with reason <code>permission_denied</code> — the app does not
hide the link, because the app is not the thing enforcing access.</p>`, webui.Esc(id.UserID)))

	body += webui.Card("Single sign-on", fmt.Sprintf(`<p>Open the smart-home application on a
different hostname. You will not be asked to log in again: the authorizer starts a fresh OIDC
flow and Keycloak answers immediately from your existing realm session.</p>%s`,
		webui.Links(smarthome, "Open Smart Home →", account, "Account &amp; consent", "/_id/logout", "Sign out")))

	webui.Page(w, "Profile App", "first-party", id, body)
}

func viewProfile(w http.ResponseWriter, r *http.Request) {
	id := webui.From(r)
	userID, _ := svc.PathTail(r.URL.Path, "/profile")
	if userID == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	res, err := profileSvc.Do(r.Context(), r, http.MethodGet, "/api/profile/"+userID, nil)
	if err != nil {
		svc.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	wantsJSON := strings.Contains(r.Header.Get("accept"), "application/json")

	if !res.OK() {
		if wantsJSON {
			w.Header().Set("content-type", "application/json")
			if res.Reason != "" {
				w.Header().Set("x-authz-reason", res.Reason)
			}
			w.WriteHeader(res.Status)
			_, _ = w.Write(res.Body)
			return
		}
		webui.Page(w, "Profile App", "first-party", id, webui.Card("Denied", fmt.Sprintf(
			`<p>%s The request reached profile-service's sidecar and was refused there —
this application never received the data.</p><dl><dt>Status</dt><dd>%d</dd>
<dt>Reason</dt><dd>%s</dd><dt>Detail</dt><dd>%s</dd></dl>%s`,
			webui.Pill("no", "permission denied"), res.Status, webui.Esc(res.Reason),
			webui.Esc(res.Detail()), webui.Links("/", "← Back"))))
		return
	}

	var p profile
	if err := res.JSON(&p); err != nil {
		svc.WriteError(w, http.StatusBadGateway, "malformed upstream response")
		return
	}
	if wantsJSON {
		svc.WriteJSON(w, http.StatusOK, p)
		return
	}
	webui.Page(w, "Profile App", "first-party", id, webui.Card(p.Name, fmt.Sprintf(
		`<dl><dt>User id</dt><dd>%s</dd><dt>Email</dt><dd>%s</dd>
<dt>Phone</dt><dd>%s</dd><dt>Address</dt><dd>%s</dd></dl>
<p class="note">%s No consent prompt appeared. This application is registered first-party,
so the user acting on their own data through their own app is not a third-party disclosure.</p>%s`,
		webui.Esc(p.UserID), webui.Esc(p.Email), webui.Esc(p.Phone), webui.Esc(p.Address),
		webui.Pill("ok", "permitted"), webui.Links("/", "← Back"))))
}

// static exists so that asset paths are matched by their own authorization
// rule and can never be captured by a parameterised pattern — mvp_docs/06
// hazard 3, which the cityos README documents as a real problem.
func static(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, ".css") {
		w.Header().Set("content-type", "text/css")
		_, _ = w.Write([]byte("/* styles are inlined; this path exists to prove the rule */\n"))
		return
	}
	http.NotFound(w, r)
}

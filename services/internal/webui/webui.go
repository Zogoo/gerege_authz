// Package webui renders the demonstration pages.
//
// The applications are deliberately thin. Everything interesting has already
// happened by the time a request reaches them: the pages exist to make the
// three identities and the authorization outcome visible to a person watching
// a browser (mvp_docs/02 §3).
package webui

import (
	"fmt"
	"html"
	"net/http"
	"strings"
)

// Identity is what ext-authz asserted about the caller.
//
// mvp_docs/04 §2.2: applications must not treat these headers as a security
// boundary of their own. They are informational — the authorization decision
// was already made before the request arrived.
type Identity struct {
	UserID      string
	UserName    string
	Application string
	DecisionID  string
}

// From reads the headers ext-authz injects on a permit.
func From(r *http.Request) Identity {
	return Identity{
		UserID:      r.Header.Get("x-user-id"),
		UserName:    r.Header.Get("x-user-name"),
		Application: r.Header.Get("x-application"),
		DecisionID:  r.Header.Get("x-authz-decision-id"),
	}
}

const style = `
:root{--bg:#f6f7f9;--card:#fff;--fg:#14171c;--muted:#5d6673;--line:#e2e5ea;
--accent:#2f5fd0;--ok:#137a4a;--okbg:#e6f5ec;--no:#a3282a;--nobg:#fdecec;--warnbg:#fff6e0;--warn:#8a5b00}
@media (prefers-color-scheme:dark){:root{--bg:#12151a;--card:#1a1e25;--fg:#e8ebf0;--muted:#98a2b3;
--line:#2a3038;--accent:#7aa2f7;--ok:#4ade80;--okbg:#10251a;--no:#f87171;--nobg:#2a1414;--warnbg:#2a2210;--warn:#facc15}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:28px 20px 64px}
header{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:6px}
h1{font-size:22px;margin:0;letter-spacing:-.01em}
.tag{font:11px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;text-transform:uppercase;
letter-spacing:.08em;color:var(--muted);border:1px solid var(--line);border-radius:99px;padding:1px 9px}
.sub{color:var(--muted);margin:0 0 22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin:0 0 16px}
.card h2{font-size:13px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin:0 0 12px}
dl{display:grid;grid-template-columns:minmax(120px,auto) 1fr;gap:7px 18px;margin:0}
dt{color:var(--muted);font-size:13px}
dd{margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
tr:last-child td{border-bottom:none}
a{color:var(--accent)}
.row{display:flex;gap:9px;flex-wrap:wrap;align-items:center}
button,.btn{font:inherit;font-size:14px;padding:7px 14px;border-radius:7px;border:1px solid var(--line);
background:var(--card);color:var(--fg);cursor:pointer;text-decoration:none;display:inline-block}
button:hover,.btn:hover{border-color:var(--accent);color:var(--accent)}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.primary:hover{opacity:.9;color:#fff}
button.danger{color:var(--no);border-color:var(--no)}
.pill{display:inline-block;font-size:12px;padding:2px 9px;border-radius:99px;font-weight:600}
.pill.ok{background:var(--okbg);color:var(--ok)}
.pill.no{background:var(--nobg);color:var(--no)}
.pill.warn{background:var(--warnbg);color:var(--warn)}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:12px;overflow-x:auto;
font-size:12.5px;margin:0}
.note{font-size:13px;color:var(--muted);margin:12px 0 0}
.foot{margin-top:26px;font-size:12.5px;color:var(--muted)}
.foot code{font-size:12px}
`

// Page renders a full HTML document.
func Page(w http.ResponseWriter, title, tag string, id Identity, body string) {
	w.Header().Set("content-type", "text/html; charset=utf-8")
	w.Header().Set("cache-control", "no-store")
	fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s — Gerege IdP MVP</title><style>%s</style></head><body><div class="wrap">
<header><h1>%s</h1><span class="tag">%s</span></header>
%s
%s
<p class="foot">Every request on this page passed through an Envoy sidecar and the
external authorizer before reaching this service. Nothing here decided whether you
may see it. Decision id <code>%s</code>.</p>
</div></body></html>`,
		html.EscapeString(title), style, html.EscapeString(title), html.EscapeString(tag),
		identityCard(id), body, html.EscapeString(id.DecisionID))
}

func identityCard(id Identity) string {
	if id.UserID == "" {
		return ""
	}
	return fmt.Sprintf(`<div class="card"><h2>The three identities on this request</h2><dl>
<dt>Principal</dt><dd>%s <span class="tag">whose data</span></dd>
<dt>Application</dt><dd>%s <span class="tag">who you consented to</span></dd>
<dt>Signed in as</dt><dd>%s</dd>
</dl><p class="note">The third identity — the workload — is the mTLS peer identity of the
calling process. It never reaches the browser; it is read by the authorizer from the
check request.</p></div>`,
		html.EscapeString(id.UserID), html.EscapeString(id.Application), html.EscapeString(id.UserName))
}

// Card wraps content in a titled panel.
func Card(title, body string) string {
	return fmt.Sprintf(`<div class="card"><h2>%s</h2>%s</div>`, html.EscapeString(title), body)
}

// Pill renders a coloured status label.
func Pill(kind, text string) string {
	return fmt.Sprintf(`<span class="pill %s">%s</span>`, kind, html.EscapeString(text))
}

// Esc escapes text for interpolation into HTML.
func Esc(s string) string { return html.EscapeString(s) }

// Pre renders preformatted output.
func Pre(s string) string { return "<pre>" + html.EscapeString(s) + "</pre>" }

// Links renders a row of buttons.
func Links(pairs ...string) string {
	var b strings.Builder
	b.WriteString(`<div class="row">`)
	for i := 0; i+1 < len(pairs); i += 2 {
		fmt.Fprintf(&b, `<a class="btn" href="%s">%s</a>`, html.EscapeString(pairs[i]), html.EscapeString(pairs[i+1]))
	}
	b.WriteString(`</div>`)
	return b.String()
}

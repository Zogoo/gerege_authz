# -*- coding: utf-8 -*-
"""Generates mvp/docs/architecture.svg — the MVP system architecture diagram.

Everything drawn here is taken from the manifests and code actually deployed:
namespaces, ServiceAccounts, ports, the extension provider, the route rules and
the arrows that exist at runtime. Nothing is aspirational.
"""
import html

W, H = 1700, 1292

# ---------------------------------------------------------------- palette ----
BG      = "#ffffff"
INK     = "#151a21"
MUTED   = "#5b6673"
FAINT   = "#8c96a3"
LINE    = "#d3d9e0"
CARD    = "#ffffff"

NS = {
    "istio":  dict(fill="#eef3fe", stroke="#c9d8f8", label="#3355c9"),
    "apps":   dict(fill="#f7f8fa", stroke="#dee2e8", label="#4a5563"),
    "id":     dict(fill="#fdf7ec", stroke="#eedcbe", label="#a06a10"),
    "dev":    dict(fill="#f6f3ff", stroke="#ddd4fb", label="#6d33d0"),
}

REQ    = "#2563eb"   # request path
CHECK  = "#d97706"   # ext_authz Check — the subject of the diagram
PERM   = "#15803d"   # SpiceDB
IDENT  = "#7c3aed"   # Keycloak / identity
STORE  = "#8c96a3"   # datastore
AGENT  = "#be185d"   # an agent acting under delegation

out = []
def e(s): out.append(s)
def esc(s): return html.escape(str(s), quote=True)

def text(x, y, s, size=11.5, fill=INK, weight="normal", anchor="start",
         family=None, ls=None, halo=False, opacity=None):
    attrs = [f'x="{x}" y="{y}"', f'font-size="{size}"', f'fill="{fill}"']
    if weight != "normal": attrs.append(f'font-weight="{weight}"')
    if anchor != "start":  attrs.append(f'text-anchor="{anchor}"')
    if family:             attrs.append(f'font-family="{family}"')
    if ls:                 attrs.append(f'letter-spacing="{ls}"')
    if opacity:            attrs.append(f'opacity="{opacity}"')
    if halo:               attrs.append(f'stroke="{BG}" stroke-width="4" stroke-linejoin="round" paint-order="stroke"')
    e(f'<text {" ".join(attrs)}>{esc(s)}</text>')

MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

def box(x, y, w, h, fill, stroke, r=12, sw=1, dash=None, opacity=None):
    a = [f'x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}"',
         f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}"']
    if dash: a.append(f'stroke-dasharray="{dash}"')
    if opacity: a.append(f'opacity="{opacity}"')
    e(f'<rect {" ".join(a)}/>')

def nsbox(x, y, w, h, kind, label, sub=None):
    c = NS[kind]
    box(x, y, w, h, c["fill"], c["stroke"], r=14)
    text(x + 16, y + 22, label, 11.5, c["label"], "bold", ls="1.1")
    if sub:
        text(x + 16 + 9.0 * len(label) + 14, y + 22, sub, 10.5, c["label"], opacity="0.8")

def card(x, y, w, h, title, sub=None, lines=None, accent=None, mono_lines=False,
         title_size=14.5, fill=CARD):
    box(x, y, w, h, fill, accent or LINE, r=10, sw=2 if accent else 1)
    if accent:
        e(f'<rect x="{x}" y="{y}" width="5" height="{h}" rx="2.5" fill="{accent}"/>')
    cx = x + (20 if accent else 16)
    ty = y + 26
    text(cx, ty, title, title_size, INK, "bold")
    if sub:
        ty += 17
        text(cx, ty, sub, 11, MUTED)
    if lines:
        ty += 9
        for ln in lines:
            ty += 16.5
            fam = MONO if mono_lines else None
            text(cx, ty, ln, 11, MUTED, family=fam)
    return ty

def chip(x, y, label, fill, w=None):
    w = w or (7.2 * len(label) + 18)
    e(f'<rect x="{x}" y="{y}" width="{w}" height="19" rx="9.5" fill="{fill}" opacity="0.14"/>')
    text(x + w / 2, y + 13.5, label, 10, fill, "bold", anchor="middle")
    return w

def path(pts, color, width=1.7, dash=None, marker=True, opacity=None):
    d = " ".join(f"{'M' if i == 0 else 'L'}{px},{py}" for i, (px, py) in enumerate(pts))
    a = [f'd="{d}"', f'fill="none"', f'stroke="{color}"', f'stroke-width="{width}"',
         'stroke-linejoin="round"', 'stroke-linecap="round"']
    if dash: a.append(f'stroke-dasharray="{dash}"')
    if marker: a.append(f'marker-end="url(#a-{color[1:]})"')
    if opacity: a.append(f'opacity="{opacity}"')
    e(f'<path {" ".join(a)}/>')

def alabel(x, y, s, color, anchor="middle", size=10.5):
    text(x, y, s, size, color, "bold", anchor=anchor, halo=True)

# ================================================================== header ===
e(f'<rect width="{W}" height="{H}" fill="{BG}"/>')
text(60, 46, "Gerege IdP — MVP system architecture", 25, INK, "bold")
text(60, 72,
     "Every request into an application passes an Envoy sidecar that consults one Go authorizer, which answers from SpiceDB. "
     "Keycloak only says who you are — and an agent holding your token is bound by what you delegated, not by what you can do.",
     13.5, MUTED)

# =========================================================== top-row panels ==
# --- three identities -------------------------------------------------------
PX, PY, PW, PH = 60, 104, 392, 144
box(PX, PY, PW, PH, "#fbfcfd", LINE, r=12)
text(PX + 16, PY + 25, "THE IDENTITIES ON A REQUEST", 10.5, MUTED, "bold", ls="0.9")
rows = [("Principal", "token sub", "who is accountable"),
        ("Application", "token azp", "who the user consented to"),
        ("Agent", "azp after RFC 8693", "what is acting, under delegation"),
        ("Workload", "source.principal", "which process is calling")]
ry = PY + 44
for name, src, ans in rows:
    text(PX + 16, ry + 10, name, 11.5, INK, "bold")
    text(PX + 104, ry + 10, src, 10.5, MUTED, family=MONO)
    text(PX + 236, ry + 10, ans, 10.5, FAINT)
    ry += 22

# --- browser ----------------------------------------------------------------
card(478, 104, 330, 144, "Browser  ·  Alice", "opaque session cookie — never a token",
     ["profile.local.test", "smarthome.local.test", "account.local.test"], mono_lines=True)

# --- terminal ---------------------------------------------------------------
card(830, 104, 330, 144, "Terminal", "the same system, scripted",
     ["make verify   29 assertions", "make demo     6 scenarios", "curl + Bearer token"],
     mono_lines=True)

# --- legend -----------------------------------------------------------------
LX, LY, LW, LH = 1194, 104, 454, 144
box(LX, LY, LW, LH, "#fbfcfd", LINE, r=12)
text(LX + 16, LY + 25, "EDGES", 10.5, MUTED, "bold", ls="0.9")
leg = [(REQ,   "solid", "request path"),
       (CHECK, "solid", "ext_authz Check (gRPC) — fail-closed"),
       (REQ,   "dash",  "internal hop — authorized again at the callee"),
       (AGENT, "solid", "agent acting under delegation"),
       (PERM,  "solid", "SpiceDB: permission, consent, delegation"),
       (IDENT, "solid", "Keycloak: tokens, keys, RFC 8693 exchange"),
       (STORE, "solid", "datastore")]
ly = LY + 40
for col, style, label in leg:
    w = 3.2 if col == CHECK else 1.8
    da = ' stroke-dasharray="5 4"' if style == "dash" else ""
    e(f'<line x1="{LX+16}" y1="{ly}" x2="{LX+52}" y2="{ly}" stroke="{col}" '
      f'stroke-width="{w}" stroke-linecap="round"{da}/>')
    e(f'<polygon points="{LX+52},{ly} {LX+45},{ly-3.4} {LX+45},{ly+3.4}" fill="{col}"/>')
    text(LX + 62, ly + 3.6, label, 10.8, MUTED)
    ly += 13.6

# ============================================================ kind cluster ===
KX, KY, KW, KH = 56, 250, 1596, 988
box(KX, KY, KW, KH, "#fcfcfd", "#c9ced6", r=18, dash="7 5")
text(KX + 20, KY + 24, "KIND CLUSTER  ·  gerege-idp  ·  kubernetes v1.36.1  ·  one node  ·  host :80 → NodePort 30080",
     11, "#7d8894", "bold", ls="0.6")

# ------------------------------------------------ ns istio-system + devices --
nsbox(84, 288, 908, 196, "istio", "ns istio-system")
card(106, 320, 284, 146, "istiod", "mesh control plane",
     ["extensionProvider:", "  gerege-ext-authz", "  → ext-authz.id:9001", "  failOpen: false"],
     mono_lines=True, title_size=14)
card(406, 320, 568, 146, "istio-ingressgateway", "NodePort 30080  ←  host :80",
     ["AuthorizationPolicy CUSTOM → gerege-ext-authz   (4 hosts)",
      "profile · smarthome · account · device   →   workloads below",
      "id.local.test → Keycloak   — deliberately NOT sent to ext-authz",
      "PeerAuthentication STRICT downstream: mTLS to every sidecar"], title_size=14)

nsbox(1080, 288, 568, 196, "dev", "ns devices", "no injection · outside the mesh")
card(1102, 320, 524, 146, "telemetry-simulator", "an IoT device, holding only a token",
     ["client_credentials → sensor-1   (no user, no consent)",
      "every 20s:  1 request permitted,  3 refused",
      "own telemetry ✓   ·   thermostat-1 ✗   ·   alice's profile ✗   ·   no token ✗"], title_size=14)

# ------------------------------------------------------------------ ns apps --
nsbox(84, 508, 908, 712, "apps", "ns apps",
      "istio-injection=enabled · PeerAuthentication STRICT · AuthorizationPolicy CUSTOM (namespace-wide)")
APP_X, APP_W = 146, 806
apps = [
    (552, "profile-app",       "sa/profile-app  ·  browser UI, first-party",
     "consent declared but suppressed — a user acting on their own data through their own app", None),
    (665, "profile-service",   "sa/profile-service  ·  profile data API, internal only",
     "no authorization logic in this service. look for it: there is none", None),
    (778, "smarthome-service", "sa/smarthome-service  ·  browser UI + API, third-party",
     "consent enforced — the azp claim is the only thing that differs", None),
    (891, "agent-runner",      "sa/agent-runner  ·  the agent",
     "RFC 8693 exchange: sub stays alice, azp becomes the agent — then it acts, bound by the delegation", AGENT),
    (1004, "device-service",   "sa/device-service  ·  device state + /telemetry ingest",
     "/internal/* callable only by smarthome-service and agent-runner; /telemetry only by the device", None),
]
for y, name, sub, note, accent in apps:
    card(APP_X, y, APP_W, 100, name, sub, [note], accent=accent)
    e(f'<rect x="{APP_X+APP_W-104}" y="{y+12}" width="90" height="20" rx="10" '
      f'fill="{REQ}" opacity="0.10"/>')
    text(APP_X + APP_W - 59, y + 26, "envoy sidecar", 9.5, REQ, "bold", anchor="middle")
    text(APP_X + APP_W - 14, y + 48, ":8080   health :8081 not intercepted", 9.5, FAINT,
         anchor="end", family=MONO)

text(106, 1180, "Every internal hop is authorized again at the callee's own sidecar — the same identities, a different question.",
     11, NS["apps"]["label"])
text(106, 1198, "A gateway-only architecture never gets to ask the second one.", 11, NS["apps"]["label"], opacity="0.75")

# -------------------------------------------------------------------- ns id --
nsbox(1080, 508, 568, 712, "id", "ns id", "the identity and authorization plane · STRICT mTLS on account-app")

EA_X, EA_Y, EA_W, EA_H = 1102, 552, 524, 318
card(EA_X, EA_Y, EA_W, EA_H, "ext-authz", "Go · envoy.service.auth.v3 gRPC :9001 · the decision point",
     accent=CHECK, title_size=16)
steps = [
    ("1", "OIDC callback and logout — before any authorization"),
    ("2", "principal   ←  bearer token, or session → token"),
    ("3", "application ← azp   ·   workload ← source.principal"),
    ("4", "match a route rule   —   no match → DENY"),
    ("5", "is this workload registered for this application?"),
    ("6", "step-up gate  —  agents cannot pass"),
    ("7", "CheckBulkPermissions [ permission, consent | delegation ]"),
    ("8", "emit a decision record  —  principal AND actor"),
]
sy = EA_Y + 78
for n, s in steps:
    e(f'<circle cx="{EA_X+30}" cy="{sy-3.5}" r="8" fill="{CHECK}" opacity="0.16"/>')
    text(EA_X + 30, sy, n, 9.5, CHECK, "bold", anchor="middle")
    text(EA_X + 48, sy, s, 11, MUTED)
    sy += 21
e(f'<line x1="{EA_X+18}" y1="{sy-4}" x2="{EA_X+EA_W-18}" y2="{sy-4}" stroke="{LINE}"/>')
text(EA_X + 20, sy + 16, "read-only on SpiceDB   ·   no decision cache   ·   every error path denies",
     11, CHECK, "bold")
text(EA_X + 20, sy + 33, "22 rules · defaultAction DENY · health :9002 · decision log :9003 (pod-only)",
     10.5, FAINT, family=MONO)

card(1180, 900, 292, 106, "account-app", "sa/account-app · consent + delegation",
     ["the ONLY component that writes", "consent or delegations"], title_size=14)
card(1102, 1022, 248, 96, "Keycloak 26.7.2", "login · SSO · RFC 8693 exchange",
     ["authentication only —", "holds no authorization state"], title_size=14)
card(1372, 1022, 254, 96, "SpiceDB 1.56.0", "Zanzibar relationships",
     ["permission · consent ·", "delegation (with expiry)"], title_size=14)
card(1102, 1130, 248, 68, "PostgreSQL 18.6", "keycloak", title_size=12.5)
card(1372, 1130, 254, 68, "PostgreSQL 18.6", "spicedb · track_commit_timestamp=on", title_size=12.5)

# =================================================================== arrows ==
GW_R = 974                     # gateway right edge
RAIL_REQ, RAIL_CHK = 1012, 1048
APP_R = APP_X + APP_W          # 952
ID_L = 1102                    # ext-authz / keycloak left edge

# --- browser and terminal into the gateway ----------------------------------
path([(620, 248), (620, 320)], REQ, 2.2)
alabel(620, 288, "http  :80", REQ)
path([(944, 248), (944, 320)], REQ, 2.2)
alabel(944, 288, "Bearer", REQ)

# --- the device into the gateway --------------------------------------------
path([(1102, 380), (974, 380)], REQ, 2.2)
alabel(1038, 366, "Host: device.local.test", REQ, size=9.5)

# --- ingress routing rail ----------------------------------------------------
path([(GW_R, 440), (RAIL_REQ, 440), (RAIL_REQ, 1070)], REQ, 2.2, marker=False)
alabel(RAIL_REQ - 6, 498, "routes by", REQ, anchor="end", size=10)
alabel(RAIL_REQ - 6, 510, "Host header", REQ, anchor="end", size=10)
for y in (578, 804, 1030):
    path([(RAIL_REQ, y), (APP_R, y)], REQ, 1.8)
path([(RAIL_REQ, 936), (1180, 936)], REQ, 1.8)
path([(RAIL_REQ, 1070), (ID_L, 1070)], REQ, 1.8)

# --- the ext_authz rail: the subject of the diagram --------------------------
path([(GW_R, 424), (RAIL_CHK, 424), (RAIL_CHK, 1076)], CHECK, 3.2, marker=False)
for y in (632, 745, 858, 971, 1076):
    path([(APP_R, y), (RAIL_CHK, y)], CHECK, 2.4, marker=False)
    e(f'<circle cx="{RAIL_CHK}" cy="{y}" r="3.6" fill="{CHECK}"/>')
path([(1180, 978), (RAIL_CHK, 978)], CHECK, 2.4, marker=False)
for y in (424, 978):
    e(f'<circle cx="{RAIL_CHK}" cy="{y}" r="3.6" fill="{CHECK}"/>')
path([(RAIL_CHK, 700), (ID_L, 700)], CHECK, 3.4)
alabel(1075, 684, "Check", CHECK, size=11)
alabel(1075, 672, "every request", CHECK, size=9.5)

# --- internal service-to-service hops ---------------------------------------
# Blue: a service calling another service. Pink: the agent calling, with an
# identity of its own and only the authority Alice delegated to it.
hops = [
    (800, 1060, 92,  REQ,   "smarthome-service → device-service"),
    (940, 730,  104, AGENT, "agent-runner → profile-service"),
    (830, 915,  116, REQ,   "smarthome-service → agent-runner"),
    (602, 700,  128, REQ,   "profile-app → profile-service"),
    (965, 1030, 140, AGENT, "agent-runner → device-service"),
]
for a, b, rail, colour, _ in hops:
    path([(APP_X, a), (rail, a), (rail, b), (APP_X, b)], colour, 1.8, dash="5 4")
    e(f'<circle cx="{APP_X}" cy="{a}" r="3.2" fill="{colour}"/>')

# --- the agent trades Alice's token for one of its own -----------------------
path([(APP_R, 928), (1088, 928), (1088, 1064), (ID_L, 1064)], AGENT, 2.2)
alabel(1020, 920, "RFC 8693", AGENT, size=9.5)
alabel(1020, 909, "exchange", AGENT, size=9.5)

# --- ext-authz outbound ------------------------------------------------------
path([(1140, 870), (1140, 1022)], IDENT, 2.0)
alabel(1148, 884, "JWKS · code exchange", IDENT, anchor="start", size=9.5)

path([(1604, 870), (1604, 1022)], PERM, 2.6)
alabel(1596, 884, "CheckBulkPermissions [ permission, consent | delegation ]",
       PERM, anchor="end", size=9.5)

# --- account-app is the only component that writes ---------------------------
path([(1472, 953), (1548, 953), (1548, 1022)], PERM, 2.4)
alabel(1552, 980, "writes consent", PERM, anchor="start", size=9.5)
alabel(1552, 992, "and delegations", PERM, anchor="start", size=9.5)

# --- datastores --------------------------------------------------------------
path([(1226, 1118), (1226, 1130)], STORE, 1.8)
path([(1499, 1118), (1499, 1130)], STORE, 1.8)

# ---------------------------------------------------------------- footnote ---
text(60, 1264,
     "Fail-closed by construction:  failOpen: false at the mesh  ·  defaultAction DENY in the route document  ·  "
     "every error branch in ext-authz returns a denial  ·  SpiceDB unreachable → nothing is permitted.",
     11.5, MUTED)
text(60, 1282,
     "An agent adds one actor, one grant and one gate:  it is registered rather than inferred  ·  its authority is an expiring delegation, not the token it holds  ·  "
     "and a step-up route refuses it outright, because it cannot re-authenticate the person behind it.",
     11.5, AGENT)

# ---------------------------------------------------------------- assemble ---
markers = "".join(
    f'<marker id="a-{c[1:]}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" '
    f'markerHeight="6.5" orient="auto-start-reverse">'
    f'<path d="M0,1 L10,5 L0,9 z" fill="{c}"/></marker>'
    for c in (REQ, CHECK, PERM, IDENT, STORE, AGENT))

svg = (
    f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
    f'role="img" aria-label="Gerege IdP MVP system architecture: browsers, a terminal and an IoT '
    f'device reach an Istio ingress gateway; the gateway and every application sidecar call one Go '
    f'external authorizer over gRPC, which answers from SpiceDB; Keycloak provides identity only." '
    f'font-family="Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Helvetica, Arial, sans-serif">'
    f'<defs>{markers}</defs>' + "".join(out) + '</svg>')

import io, os
dst = "/Users/admin/devops-worspace/gerege_idp/mvp/docs/architecture.svg"
os.makedirs(os.path.dirname(dst), exist_ok=True)
io.open(dst, "w", encoding="utf-8").write(svg)
print("wrote", dst, len(svg), "bytes")

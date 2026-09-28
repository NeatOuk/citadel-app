"""Citadel's decision logic: rule matching, the nftables spec, proxy routes.

A function-by-function port of the Omarchy plugin's Model.js, so the daemon
and the plugin decide exactly alike. tests/test_parity.py runs generated cases
through both and compares the results; keep the two in step.

Values are plain dicts and lists, shaped like the JavaScript objects (same keys,
same insertion order), because they are sent to the helper and the front-ends
as JSON.
"""
import json
import random
import re
import string
import time

# ------------------------------------------------------------------ addresses

_V4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_V6CHARS = re.compile(r"^[0-9a-fA-F:.]+$")


def parse_ipv4(s):
    m = _V4.match(str(s))
    if not m:
        return None
    n = 0
    for i in range(1, 5):
        b = int(m.group(i))
        if b > 255:
            return None
        n = n * 256 + b
    return n


def _num(x):
    """JavaScript Number(x) for the values that occur here (NaN -> None)."""
    if isinstance(x, bool):
        return 1 if x else 0
    if isinstance(x, (int, float)):
        return x
    s = str(x).strip()
    if s == "":
        return 0
    try:
        return int(s) if re.fullmatch(r"[+-]?\d+", s) else float(s)
    except ValueError:
        return None


def parse_net(s):
    text = str(s if s is not None else "").strip()
    parts = text.split("/")
    bits = _num(parts[1]) if len(parts) > 1 else None
    if len(parts) > 1 and bits is None:
        bits = float("nan")
    v4 = parse_ipv4(parts[0])
    if v4 is not None:
        if bits is None:
            bits = 32
        if not (bits == bits and 0 <= bits <= 32):
            return None
        return {"v": 4, "net": v4, "bits": bits}
    if ":" in parts[0] and _V6CHARS.match(parts[0]):
        if bits is None:
            bits = 128
        return {"v": 6, "text": expand_ipv6(parts[0]), "bits": bits}
    return None


def expand_ipv6(s):
    text = str(s).lower()
    halves = text.split("::")
    head = halves[0].split(":") if halves[0] else []
    tail = halves[1].split(":") if len(halves) > 1 and halves[1] else []
    fill = max(0, 8 - len(head) - len(tail))
    groups = head + ["0"] * fill + tail
    out = ""
    for g in groups:
        try:
            v = int(g or "0", 16)
        except ValueError:
            v = _js_parse_hex(g)
        out += format(v, "016b") if v == v else "0000000000000000"[:13] + "NaN"
    return out


def _js_parse_hex(g):
    """parseInt(g, 16): the leading hex digits, NaN when there are none."""
    m = re.match(r"^[0-9a-fA-F]+", g)
    return int(m.group(0), 16) if m else float("nan")


def is_address_like(s):
    return parse_net(s) is not None


def net_contains(net_str, ip):
    n = parse_net(net_str)
    a = parse_net(ip)
    if not n or not a or n["v"] != a["v"]:
        return False
    if n["v"] == 4:
        if n["bits"] == 0:
            return True
        shift = 32 - n["bits"]
        return int(n["net"] // (2 ** shift)) == int(a["net"] // (2 ** shift))
    b = int(n["bits"]) if n["bits"] == n["bits"] else 0
    return n["text"][:b] == a["text"][:b]


# ------------------------------------------------------------------ rules

def norm_host(h):
    s = str("*" if h is None else h).strip().lower()
    s = s[:-1] if s.endswith(".") else s
    return s or "*"


def norm_port(p):
    if p is None or p == "" or p == "*":
        return "*"
    n = _num(p)
    if n is None or not (1 <= n <= 65535):
        return "*"
    return int(n + 0.5) if n >= 0 else int(n)


def _new_id():
    t = int(time.time() * 1000)
    digits = string.digits + string.ascii_lowercase
    s = ""
    while t:
        t, r = divmod(t, 36)
        s = digits[r] + s
    return s + "".join(random.choice(digits) for _ in range(5))


def make_rule(fields=None):
    f = fields or {}
    return {
        "id": f.get("id") or _new_id(),
        "profile": f.get("profile") or "*",
        "app": f.get("app") or "*",
        "via": f.get("via") or "*",
        "host": norm_host(f.get("host")),
        "port": norm_port(f.get("port")),
        "action": "deny" if f.get("action") == "deny" else "allow",
        "route": str(f["route"]) if f.get("route") not in (None, "", False, 0) else "default",
        "duration": "untilQuit" if f.get("duration") == "untilQuit" else "forever",
        "pids": f.get("pids") or [],
        "exeHash": f.get("exeHash") or "",
        "note": f.get("note") or "",
        "origin": f["origin"] if f.get("origin") in ("gate", "you") else ("gate" if f.get("exeHash") else "you"),
        "createdAt": f.get("createdAt") or int(time.time()),
    }


def via_label(via_id):
    if not via_id or via_id == "*":
        return ""
    return str(via_id).split("/")[-1]


def filter_rules(rules, opts=None, proxy_name=None):
    o = opts or {}
    q = str(o.get("query") or "").strip().lower()
    out = []
    for r in rules or []:
        prof = o.get("profile")
        if prof and prof != "*all*" and r["profile"] != prof and r["profile"] != "*":
            continue
        routed = r["action"] == "allow" and r.get("route") and r["route"] not in ("default", "direct")
        show = o.get("show")
        if show == "you" and r.get("origin") != "you":
            continue
        if show == "gate" and r.get("origin") != "gate":
            continue
        if show == "deny" and r["action"] != "deny":
            continue
        if show == "proxy" and not routed:
            continue
        if q:
            hay = " ".join([r["app"], r["app"].split("/")[-1],
                            r["via"] + " " + via_label(r["via"]) if r.get("via") and r["via"] != "*" else "",
                            r["host"], str(r["port"]), proxy_name(r["route"]) if routed and proxy_name else "",
                            r.get("note") or ""]).lower()
            if not all(w in hay for w in q.split()):
                continue
        out.append(r)
    if o.get("sort") == "precedence":
        return sorted(out, key=lambda r: (-specificity(r), -r["createdAt"]))
    return sorted(out, key=lambda r: -r["createdAt"])


def specificity(rule):
    app = rule.get("app") and rule["app"] != "*"
    host = rule.get("host") and rule["host"] != "*"
    s = 30 if app and host else 20 if host else 10 if app else 0
    if rule.get("port", "*") != "*":
        s += 5
    if rule.get("via") and rule["via"] != "*":
        s += 3
    return s


def host_matches(rule_host, conn, resolved):
    h = norm_host(rule_host)
    if h == "*":
        return True
    if is_address_like(h):
        return net_contains(h, conn.get("raddr"))
    name = norm_host(conn.get("host"))
    if name != "*" and (name == h or name[-(len(h) + 1):] == "." + h):
        return True
    ips = resolved.get(h) if resolved else None
    return bool(ips and conn.get("raddr") in ips)


def rule_active(rule, ctx):
    if rule.get("profile") and rule["profile"] != "*" and rule["profile"] != ctx.get("profile"):
        return False
    if rule.get("duration") == "untilQuit":
        alive = ctx.get("alivePids") or {}
        return any(alive.get(str(p)) or alive.get(p) for p in rule.get("pids") or [])
    return True


def rule_matches(rule, conn, ctx):
    if not rule_active(rule, ctx):
        return False
    if rule.get("app") and rule["app"] != "*" and rule["app"] != conn.get("exe"):
        return False
    if rule.get("via") and rule["via"] != "*" and rule["via"] != (conn.get("viaId") or ""):
        return False
    if rule.get("port", "*") != "*" and _num(rule["port"]) != _num(conn.get("rport")):
        return False
    return host_matches(rule.get("host"), conn, ctx.get("resolved"))


def best_rule(conn, rules, ctx):
    best, best_score = None, -1
    for r in rules or []:
        if not rule_matches(r, conn, ctx):
            continue
        score = specificity(r) * 2 + (1 if r["action"] == "deny" else 0)
        if score > best_score:
            best, best_score = r, score
    return best


def decide(conn, rules, ctx):
    if conn.get("system"):
        return {"verdict": "system", "source": "system", "rule": None}
    r = best_rule(conn, rules, ctx)
    if r:
        return {"verdict": r["action"], "source": "rule", "rule": r}
    if conn.get("list"):
        return {"verdict": "deny", "source": "blocklist", "rule": None, "list": conn["list"]}
    s = (ctx.get("session") or {}).get(alert_key(conn)) if ctx.get("session") else None
    if s:
        return {"verdict": s, "source": "once", "rule": None}
    if ctx.get("mode") == "open":
        return {"verdict": "allow", "source": "silent", "rule": None}
    if ctx.get("mode") == "lockdown":
        return {"verdict": "deny", "source": "silent", "rule": None}
    return {"verdict": "prompt", "source": "none", "rule": None}


def _js_str(v):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


def alert_key(conn):
    host = norm_host(conn.get("host"))
    return "|".join(_js_str(x) for x in [conn.get("exe") or conn.get("app") or "?", conn.get("viaId") or "",
                                         host if host != "*" else conn.get("raddr"), conn.get("rport") or 0])


def rule_from_alert(alert, action, scope, duration, profile, app_info, via_scoped, route=None):
    conn = alert["conn"]
    host = conn.get("host") or conn.get("raddr")
    return make_rule({
        "profile": profile or "*",
        "app": conn.get("exe") or "*",
        "via": conn["viaId"] if via_scoped and conn.get("viaId") else "*",
        "route": route if action == "allow" and route else "default",
        "host": "*" if scope == "app" else host,
        "port": conn.get("rport") if scope == "hostPort" else "*",
        "action": action,
        "duration": "untilQuit" if duration == "untilQuit" else "forever",
        "pids": (app_info.get("pids") or []) if duration == "untilQuit" and app_info else [],
        "exeHash": ((app_info.get("trust") or {}).get("hash") or "") if app_info and app_info.get("trust") else "",
        "origin": "gate",
    })


# ------------------------------------------------------------------ nft spec

def _key(x):
    return x if isinstance(x, str) else json.dumps(x, separators=(",", ":"), ensure_ascii=False)


def uniq(arr):
    seen, out = set(), []
    for x in arr:
        k = _key(x)
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out


def _js_sort(values):
    """Array.prototype.sort() without a comparator: by string value."""
    return sorted(values, key=lambda v: _js_str(v))


def host_targets(rule, conns, resolved, learned):
    h = norm_host(rule.get("host"))
    port = None if rule.get("port") == "*" else rule.get("port")
    ips = []
    if is_address_like(h):
        ips.append(h)
    else:
        r = resolved.get(h) if resolved else None
        if r:
            ips += list(r)
        for c in conns:
            if not c.get("system") and host_matches(h, c, None):
                ips.append(c.get("raddr"))
        if learned and learned.get(rule["id"]):
            ips += list(learned[rule["id"]])
    return [{"ip": ip, "port": port} for ip in _js_sort(uniq(ips))]


def learn_targets(learned, rules, conns, now, ttl=None):
    out = {}
    limit = now - (ttl or 3600)
    for rid, m in (learned or {}).items():
        kept = {ip: ts for ip, ts in m.items() if ts >= limit}
        if kept:
            out[rid] = kept
    for r in rules:
        named = r["host"] != "*" and not is_address_like(r["host"])
        whole_app = r["app"] != "*" and r["host"] == "*"
        via_rule = r.get("via") and r["via"] != "*"
        if not named and not whole_app and not via_rule:
            continue
        for c in conns:
            if c.get("system"):
                continue
            if via_rule:
                hit = c.get("exe") == r["app"] and (c.get("viaId") or "") == r["via"] and host_matches(r["host"], c, None)
            else:
                hit = host_matches(r["host"], c, None) if named else c.get("exe") == r["app"]
            if not hit:
                continue
            out.setdefault(r["id"], {})
            if named or whole_app:
                out[r["id"]][c.get("raddr")] = now
            if via_rule and c.get("cgroup"):
                out[r["id"]]["cg:" + c["cgroup"]] = now
    return out


def learned_ips(learned):
    return {rid: [k for k in m if not k.startswith("cg:")] for rid, m in (learned or {}).items()}


def learned_cgroups(learned):
    return {rid: [k[3:] for k in m if k.startswith("cg:")] for rid, m in (learned or {}).items()}


def user_cgroup(cg, uid):
    return str(cg or "").startswith("user.slice/user-%s.slice/" % _js_str(uid))


def sorted_active(rules, ctx):
    active = [r for r in rules or [] if rule_active(r, ctx)]
    return sorted(active, key=lambda r: (-specificity(r), 0 if r["action"] == "deny" else 1))


def rule_targets(r, ctx, conns, apps, uid, approx):
    out = []
    has_app = r.get("app") and r["app"] != "*"
    has_host = r.get("host") and r["host"] != "*"
    port = None if r.get("port") == "*" else r.get("port")
    learned = ctx.get("learned") or {}
    if not has_app:
        t = host_targets(r, conns, ctx.get("resolved"), ctx.get("learned"))
        if t:
            out.append({"targets": t})
        return out
    if r.get("via") and r["via"] != "*":
        approx[r["id"]] = True
        lcg = (ctx.get("learnedCg") or {}).get(r["id"]) or []
        cgs = uniq([c.get("cgroup") for c in conns
                    if not c.get("system") and c.get("exe") == r["app"] and (c.get("viaId") or "") == r["via"]] + list(lcg))
        cgs = _js_sort([c for c in cgs if user_cgroup(c, uid)])
        if has_host:
            vt = host_targets(r, conns, ctx.get("resolved"), ctx.get("learned"))
        else:
            ips = uniq([c.get("raddr") for c in conns if c.get("exe") == r["app"] and (c.get("viaId") or "") == r["via"]]
                       + list(learned.get(r["id"]) or []))
            vt = [{"ip": ip, "port": port} for ip in _js_sort(ips)]
        if vt:
            for cg in cgs:
                out.append({"cgroup": cg, "targets": vt})
        return out
    info = apps.get(r["app"]) if apps else None
    if not info:
        return out
    owned = [c for c in info.get("owned") or [] if user_cgroup(c, uid)]
    all_cgs = [c for c in info.get("cgroups") or [] if user_cgroup(c, uid)]
    if has_host:
        tg = host_targets(r, conns, ctx.get("resolved"), ctx.get("learned"))
        if not tg:
            return out
        for cg in all_cgs:
            out.append({"cgroup": cg, "targets": tg})
        if len(all_cgs) > len(owned):
            approx[r["id"]] = True
        return out
    any_on_port = [{"ip": "0.0.0.0/0", "port": port}, {"ip": "::/0", "port": port}] if port else None
    for cg in owned:
        out.append({"cgroup": cg, "targets": any_on_port} if any_on_port else {"cgroup": cg})
    shared = [c for c in all_cgs if c not in owned]
    if shared:
        approx[r["id"]] = True
        dests = _js_sort(uniq([c.get("raddr") for c in conns if c.get("exe") == r["app"]]
                              + list(learned.get(r["id"]) or [])))
        if dests:
            for cg in shared:
                out.append({"cgroup": cg, "targets": [{"ip": ip, "port": port} for ip in dests]})
    return out


def build_spec(rules, ctx, conns, apps, blocklist_cidrs, uid):
    entries = []
    approx = {}
    placed = False
    for r in sorted_active(rules, ctx):
        verdict = "drop" if r["action"] == "deny" else "accept"
        if not placed and not (r.get("host") and r["host"] != "*") and r.get("app") and r["app"] != "*":
            entries.append({"blocklist": True})
            placed = True
        for m in rule_targets(r, ctx, conns, apps, uid, approx):
            entries.append(dict({"verdict": verdict}, **m))
    if not placed:
        entries.append({"blocklist": True})
    return {"spec": {"silentDeny": ctx.get("mode") == "lockdown", "blocklist": blocklist_cidrs or [], "rules": entries},
            "approx": approx}


def build_spec_darwin(rules, ctx, prefs, default_route="direct", proxies=None):
    """The spec for the macOS network extension. It decides each new
    connection itself with CitadelCore (the Swift port of this module), so it
    gets the policies and the context rather than compiled cgroup/IP rules."""
    p = prefs or {}
    return {"format": "citadel-macos-1",
            "rules": list(rules or []),               # CitadelCore applies zones and until-quit itself
            "ctx": {"profile": ctx.get("profile"), "mode": ctx.get("mode"), "resolved": ctx.get("resolved") or {},
                    "session": ctx.get("session") or {}, "alivePids": ctx.get("alivePids") or {}},
            "gate": {"default": "deny" if p.get("alertDefault") == "deny" else "allow",
                     "timeout": float(p.get("alertTimeout") or 90)},
            "defaultRoute": default_route or "direct", "proxies": proxies or []}


# ------------------------------------------------------------------ proxy routes

DEAD_PORT = 47000


def route_port(route, default_route, proxies_by_id):
    if not route or route == "default":
        route = default_route or "direct"
    if route == "direct":
        return None
    px = proxies_by_id.get(route)
    return px["listen"] if px else DEAD_PORT


def compile_routes(rules, default_route, proxies, ctx, conns, apps, uid):
    by_id = {p["id"]: p for p in proxies or []}
    out = []
    any_routed = False
    approx = {}
    for r in sorted_active(rules, ctx):
        if r["action"] == "deny" or not r.get("route") or r["route"] == "default":
            continue
        port = route_port(r["route"], default_route, by_id)
        if port is not None:
            any_routed = True
        for m in rule_targets(r, ctx, conns, apps, uid, approx):
            out.append(dict({"verdict": "direct"} if port is None else {"verdict": "redirect", "port": port}, **m))
    default_port = route_port("default", default_route, by_id)
    if not any_routed and default_port is None:
        return None
    exclude = []
    for p in proxies or []:
        ips = [p["host"]] if is_address_like(p["host"]) else ((ctx.get("resolved") or {}).get(norm_host(p["host"])) or [])
        exclude += list(ips)
    return {"rules": out, "defaultPort": default_port, "exclude": uniq(exclude)[:64]}


def route_for(conn, rules, ctx, default_route, proxies):
    if not conn or conn.get("system"):
        return None
    r = best_rule(conn, rules, ctx)
    if r and r["action"] == "deny":
        return None
    routed = best_rule(conn, [x for x in rules or [] if x["action"] == "allow" and x.get("route")
                              and x["route"] != "default"], ctx)
    route = routed["route"] if routed else (default_route or "direct")
    if route == "direct":
        return None
    for p in proxies or []:
        if p["id"] == route:
            return p
    return {"id": route, "name": "missing proxy", "missing": True}


def free_listen_port(proxies):
    used = {p.get("listen") for p in proxies or []}
    for port in range(47001, 47100):
        if port not in used:
            return port
    return 0


def route_cut_targets(prev, nxt, conns, uid):
    def key(e):
        return json.dumps([e.get("verdict"), e.get("port") or 0, e.get("cgroup") or "", e.get("targets") or []],
                          separators=(",", ":"))
    prev_rules = (prev or {}).get("rules") or []
    next_rules = (nxt or {}).get("rules") or []
    before = {key(e) for e in prev_rules}
    after = {key(e) for e in next_rules}
    changed = [e for e in next_rules if key(e) not in before] + [e for e in prev_rules if key(e) not in after]
    if not changed:
        return []
    exclude = list((nxt or {}).get("exclude") or []) + list((prev or {}).get("exclude") or [])

    def pred(c):
        if c.get("proto") != "tcp" or c.get("scope") == "loopback":
            return False
        if any(net_contains(x, c.get("raddr")) for x in exclude):
            return False
        for e in changed:
            if e.get("cgroup") and e["cgroup"] != c.get("cgroup"):
                continue
            if not e.get("targets"):
                return True
            for t in e["targets"]:
                if net_contains(t["ip"], c.get("raddr")) and (t.get("port") is None or _num(t["port"]) == _num(c.get("rport"))):
                    return True
        return False
    return kill_targets(conns, pred, uid)


def kill_targets(conns, pred, uid):
    out = []
    for c in conns:
        if c.get("system") or not user_cgroup(c.get("cgroup"), uid):
            continue
        if pred(c):
            out.append({"cgroup": c.get("cgroup"), "ip": c.get("raddr")})
    return uniq(out)


# ------------------------------------------------------------------ profiles

def active_profile(profiles, override, network_names):
    if override:
        for p in profiles:
            if p["name"] == override:
                return override
    names = network_names or []
    for p in profiles:
        for n in p.get("networks") or []:
            if n in names:
                return p["name"]
    return profiles[0]["name"] if profiles else "Default"


# ------------------------------------------------------------------ helper gate

def version_less(a, b):
    x, y = str(a).split("."), str(b).split(".")
    for i in range(3):
        xa = _num(x[i]) if i < len(x) else 0
        yb = _num(y[i]) if i < len(y) else 0
        d = (xa or 0) - (yb or 0)
        if d != 0:
            return d < 0
    return False


BAD_HELPERS = ["1.2.0"]


def helper_gate(installed, version, minimum):
    if not installed:
        return {"usable": False, "reason": "missing"}
    if not version:
        return {"usable": False, "reason": "checking"}
    if version_less(version, minimum) or str(version) in BAD_HELPERS:
        return {"usable": False, "reason": "outdated"}
    return {"usable": True, "reason": ""}


# ------------------------------------------------------------------ grouping

def group_by_app(conns, decisions):
    by = {}
    for c in conns:
        k = "system:" + _js_str(c.get("app")) if c.get("system") else \
            _js_str(c.get("exe") or c.get("app")) + ("|" + c["viaId"] if c.get("viaId") else "")
        g = by.get(k) or {"key": k, "app": c.get("app"), "exe": c.get("exe"), "system": bool(c.get("system")),
                          "conns": [], "via": c.get("via") or "", "viaId": c.get("viaId") or "",
                          "viaKind": c.get("viaKind") or "", "up": 0, "down": 0, "upRate": 0, "downRate": 0,
                          "denied": 0, "prompts": 0}
        g["conns"].append(c)
        g["up"] += c.get("up") or 0
        g["down"] += c.get("down") or 0
        g["upRate"] += c.get("upRate") or 0
        g["downRate"] += c.get("downRate") or 0
        d = decisions.get(c.get("key")) if decisions else None
        if d and d.get("verdict") == "deny":
            g["denied"] += 1
        if d and d.get("verdict") == "prompt":
            g["prompts"] += 1
        by[k] = g
    return sorted(by.values(), key=lambda g: (1 if g["system"] else 0,
                                              -(g["upRate"] + g["downRate"]), -(g["up"] + g["down"])))

"""Parity: citadel/model.py must decide exactly like the plugin's Model.js.

Generates random rules, connections and apps (fixed seeds), runs each call
through Node (Model.js) and Python, and compares the JSON results. Skipped when
node is not installed. The Model.js used is app/qml/Model.js, or
$CITADEL_MODEL_JS (e.g. the Omarchy plugin's copy).
"""
import json
import os
import random
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from citadel import model as M  # noqa: E402

MODEL_JS = os.environ.get("CITADEL_MODEL_JS") or os.path.join(ROOT, "app", "qml", "Model.js")
RUNNER = os.path.join(HERE, "js", "run_model.js")

UID = 1000
SLICE = "user.slice/user-1000.slice/user@1000.service/app.slice/"
EXES = ["/usr/bin/curl", "/usr/lib/chromium/chromium", "/opt/microsoft/msedge/msedge", "/usr/bin/git",
        "/usr/bin/python3.14", "/home/u/.local/bin/tool"]
CGS = [SLICE + "app-chromium-1.scope", SLICE + "app-ghostty-2.scope", SLICE + "app-edge-3.scope",
       "system.slice/foo.service", SLICE + "app-term-4.scope"]
HOSTS = ["*", "*", "example.com", "www.google.com", "google.com", "10.0.0.0/8", "142.250.1.1", "2606:4700::/32",
         "ads.example.com", "192.168.1.0/24", "Example.COM."]
IPS = ["142.250.1.1", "93.184.216.34", "10.1.2.3", "192.168.1.5", "2606:4700::1111", "1.1.1.1", "142.250.9.9"]
NAMES = ["", "", "www.google.com", "example.com", "ads.example.com", "cdn.example.com", "one.one.one.one"]
VIAS = ["*", "*", "*", "/home/u/bin/speedtest", "/usr/bin/ghostty"]
PROXIES = [{"id": "p1", "name": "Office", "type": "http", "host": "192.168.1.3", "port": 8080, "listen": 47001},
           {"id": "p2", "name": "Home", "type": "socks5", "host": "proxy.example", "port": 1080, "listen": 47002}]


def gen_rule(rnd, i):
    return M.make_rule({
        "id": "r%d" % i, "profile": rnd.choice(["*", "*", "Home", "Work"]),
        "app": rnd.choice(["*"] + EXES), "via": rnd.choice(VIAS), "host": rnd.choice(HOSTS),
        "port": rnd.choice(["*", "*", 443, 80, "53"]), "action": rnd.choice(["allow", "deny"]),
        "route": rnd.choice(["default", "default", "direct", "p1", "p2", "gone"]),
        "duration": rnd.choice(["forever", "forever", "untilQuit"]), "pids": rnd.choice([[], [11], [12, 13]]),
        "exeHash": rnd.choice(["", "abc"]), "createdAt": rnd.randint(1, 1000)})


def gen_conn(rnd, i):
    exe = rnd.choice(EXES)
    return {"key": "k%d" % i, "exe": exe, "app": exe.split("/")[-1], "raddr": rnd.choice(IPS),
            "rport": rnd.choice([443, 80, 53, 8080]), "host": rnd.choice(NAMES), "proto": rnd.choice(["tcp", "udp"]),
            "cgroup": rnd.choice(CGS), "system": rnd.random() < 0.1, "viaId": rnd.choice(["", "", "/home/u/bin/speedtest"]),
            "via": "", "viaKind": "", "scope": rnd.choice(["internet", "lan", "loopback"]),
            "up": rnd.randint(0, 5000), "down": rnd.randint(0, 5000), "upRate": rnd.randint(0, 50), "downRate": rnd.randint(0, 50),
            "list": rnd.choice(["", "", "", "stevenblack"])}


def gen_apps(rnd):
    apps = {}
    for exe in EXES:
        if rnd.random() < 0.8:
            cgs = rnd.sample(CGS, rnd.randint(1, 3))
            apps[exe] = {"cgroups": cgs, "owned": [c for c in cgs if rnd.random() < 0.6], "pids": [1, 2]}
    return apps


def gen_ctx(rnd, rules, conns):
    learned = M.learn_targets({}, rules, conns, 1000, 3600)
    return {"profile": rnd.choice(["Home", "Work", "Default"]), "mode": rnd.choice(["guarded", "open", "lockdown"]),
            "resolved": {"example.com": ["93.184.216.34"], "google.com": ["142.250.9.9"], "proxy.example": ["203.0.113.7"]},
            "alivePids": {"11": True}, "session": {}, "learned": M.learned_ips(learned),
            "learnedCg": M.learned_cgroups(learned)}


def cases(seed):
    rnd = random.Random(seed)
    rules = [gen_rule(rnd, i) for i in range(rnd.randint(0, 12))]
    conns = [gen_conn(rnd, i) for i in range(rnd.randint(0, 10))]
    apps = gen_apps(rnd)
    ctx = gen_ctx(rnd, rules, conns)
    if conns and rnd.random() < 0.5:
        ctx["session"] = {M.alert_key(conns[0]): rnd.choice(["allow", "deny"])}
    dr = rnd.choice(["direct", "direct", "p1", "p2"])
    out = [("buildSpec", "build_spec", [rules, ctx, conns, apps, ["5.188.10.0/23"], UID]),
           ("compileRoutes", "compile_routes", [rules, dr, PROXIES, ctx, conns, apps, UID]),
           ("learnTargets", "learn_targets", [{"r0": {"1.2.3.4": 10, "5.6.7.8": 999}}, rules, conns, 1000, 100]),
           ("groupByApp", "group_by_app", [conns, {c["key"]: {"verdict": rnd.choice(["deny", "prompt", "allow"])} for c in conns}]),
           ("filterRules", "filter_rules", [rules, {"query": rnd.choice(["", "curl", "google 443", "office", "edge"]),
                                                    "show": rnd.choice(["all", "you", "gate", "deny", "proxy"]),
                                                    "sort": rnd.choice(["newest", "precedence"]),
                                                    "profile": rnd.choice(["*all*", "Home"])}, {"$proxyNames": {"p1": "Office", "p2": "Home"}}])]
    for c in conns:
        out.append(("decide", "decide", [c, rules, ctx]))
        out.append(("routeFor", "route_for", [c, rules, ctx, dr, PROXIES]))
        out.append(("alertKey", "alert_key", [c]))
    fam_rules = [M.make_rule({"id": "f%d" % i, "app": rnd.choice(FAMILY_PATHS[:9] + ["*"]), "createdAt": rnd.randint(1, 5)})
                 for i in range(rnd.randint(0, 5))] + rules
    for exe in rnd.sample(FAMILY_PATHS[:9], 3):
        out.append(("updatedFrom", "updated_from", [exe, fam_rules]))
    a = M.compile_routes(rules[: len(rules) // 2], dr, PROXIES, ctx, conns, apps, UID)
    b = M.compile_routes(rules, dr, PROXIES, ctx, conns, apps, UID)
    out.append(("routeCutTargets", "route_cut_targets", [a, b, conns, UID]))
    return out


SCALARS = [("netContains", "net_contains", ["10.0.0.0/8", "10.9.9.9"]), ("netContains", "net_contains", ["10.0.0.0/8", "11.0.0.1"]),
           ("netContains", "net_contains", ["2606:4700::/32", "2606:4700::1111"]), ("netContains", "net_contains", ["0.0.0.0/0", "1.2.3.4"]),
           ("netContains", "net_contains", ["::/0", "::1"]), ("netContains", "net_contains", ["1.2.3.4/33", "1.2.3.4"]),
           ("normHost", "norm_host", ["  Example.COM. "]), ("normHost", "norm_host", [None]), ("normPort", "norm_port", ["443"]),
           ("normPort", "norm_port", [0]), ("normPort", "norm_port", ["x"]), ("normPort", "norm_port", [80.4]),
           ("versionLess", "version_less", ["1.2.10", "1.3.0"]), ("versionLess", "version_less", ["1.3.0", "1.3"]),
           ("helperGate", "helper_gate", [True, "1.2.0", "1.1.1"]), ("helperGate", "helper_gate", [True, "1.3.0", "1.1.1"]),
           ("helperGate", "helper_gate", [True, "", "1.1.1"]), ("helperGate", "helper_gate", [False, "1.3.0", "1.1.1"]),
           ("activeProfile", "active_profile", [[{"name": "Home", "networks": ["wifi"]}, {"name": "Work", "networks": ["corp"]}], "", ["corp"]]),
           ("activeProfile", "active_profile", [[{"name": "Home", "networks": []}], "Nope", []]),
           ("freeListenPort", "free_listen_port", [PROXIES])]
FAMILY_PATHS = ["/home/u/.local/share/mise/installs/claude/2.1.281/claude", "/home/u/.local/share/mise/installs/claude/2.1.283/claude",
                "/home/u/.local/share/mise/installs/node/26.8.2/bin/node", "/home/u/.nvm/versions/node/v20.11.0/bin/node",
                "/home/u/.nvm/versions/node/v22.1.0-rc.1/bin/node", "/home/u/.asdf/installs/python/3.12.1/bin/python3.12",
                "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-claude-code-2.1.283/bin/claude",
                "/nix/store/zyxwvsrqpnmlkjihgfdcba9876543210-claude-code-2.1.290/bin/claude",
                "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-hello/bin/hello", "/usr/bin/python3.14", "/opt/app/1.2/bin/app",
                "/opt/app/1/bin/app", "relative/1.2.3/x", "", None, "/usr/lib/jvm/java-17-openjdk/bin/java", "/a/1.2.3.4.5/b"]
SCALARS += [("appFamily", "app_family", [p]) for p in FAMILY_PATHS]


def py_call(name, args):
    fn = getattr(M, name)
    args = [(lambda a: (lambda i: a["$proxyNames"].get(i, "?")))(a) if isinstance(a, dict) and "$proxyNames" in a else a
            for a in args]
    return fn(*args)


def norm(x):
    """JSON round trip; the rule dict inside decide() is compared by id."""
    return json.loads(json.dumps(x))


@unittest.skipUnless(shutil.which("node"), "node not installed")
class Parity(unittest.TestCase):
    def run_both(self, calls):
        js_in = [{"fn": js, "args": args} for js, _, args in calls]
        p = subprocess.run(["node", RUNNER, MODEL_JS], input=json.dumps(js_in), capture_output=True, text=True, check=True)
        js_out = json.loads(p.stdout)
        for (js, py, args), want in zip(calls, js_out):
            got = norm(py_call(py, json.loads(json.dumps(args))))
            self.assertEqual(got, want, "%s(%s)" % (js, json.dumps(args)[:400]))

    def test_scalars(self):
        self.run_both(SCALARS)

    def test_generated(self):
        calls = []
        for seed in range(400):
            calls += cases(seed)
        self.assertGreater(len(calls), 3000)
        self.run_both(calls)


if __name__ == "__main__":
    unittest.main()

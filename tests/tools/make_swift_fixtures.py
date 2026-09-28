#!/usr/bin/env python3
"""Write the decision cases the Swift CitadelCore must reproduce.

The expected answers come from citadel/model.py, which tests/test_parity.py
proves identical to the plugin's Model.js, so Linux, the Omarchy plugin and
the macOS Network Extension decide alike. tests/test_swift_fixtures.py
fails when this file is out of date: re-run this script and commit.
"""
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
from citadel import model as M  # noqa: E402
from tests import test_parity as T  # noqa: E402

OUT = os.path.join(ROOT, "macos", "Packages", "CitadelCore", "Tests", "CitadelCoreTests", "Fixtures", "parity.json")
SEEDS = 120


def decision(d):
    return {"verdict": d["verdict"], "source": d["source"], "rule": d["rule"]["id"] if d.get("rule") else None,
            "list": d.get("list")}


def build():
    groups = []
    for seed in range(SEEDS):
        rnd = random.Random(10_000 + seed)
        rules = [T.gen_rule(rnd, i) for i in range(rnd.randint(0, 12))]
        conns = [T.gen_conn(rnd, i) for i in range(rnd.randint(1, 10))]
        ctx = T.gen_ctx(rnd, rules, conns)
        ctx.pop("learned"), ctx.pop("learnedCg")                 # not used by decide / routeFor
        if rnd.random() < 0.5:
            ctx["session"] = {M.alert_key(conns[0]): rnd.choice(["allow", "deny"])}
        dr = rnd.choice(["direct", "direct", "p1", "p2"])
        results = []
        for c in conns:
            r = M.route_for(c, rules, ctx, dr, T.PROXIES)
            results.append({"decide": decision(M.decide(c, rules, ctx)), "alertKey": M.alert_key(c),
                            "route": r["id"] if r else None,
                            "specificity": [M.specificity(x) for x in rules] if c is conns[0] else None})
        groups.append({"rules": rules, "conns": conns, "ctx": ctx, "defaultRoute": dr, "proxies": T.PROXIES,
                       "results": results})
    nets = [["10.0.0.0/8", "10.9.9.9"], ["10.0.0.0/8", "11.0.0.1"], ["0.0.0.0/0", "1.2.3.4"], ["1.2.3.4", "1.2.3.4"],
            ["192.168.1.0/24", "192.168.2.1"], ["2606:4700::/32", "2606:4700::1111"], ["2606:4700::/32", "2606:4701::1"],
            ["::/0", "::1"], ["fe80::/10", "fe80::1"], ["10.0.0.0/8", "::1"], ["1.2.3.4/33", "1.2.3.4"], ["bad", "1.2.3.4"],
            ["2001:db8::1", "2001:db8:0:0:0:0:0:1"], ["::ffff:10.0.0.1", "::ffff:10.0.0.1"]]
    hosts = ["  Example.COM. ", "*", "", None, "a.b.c", "x."]
    ports = ["443", 80, "*", "", None, 0, 70000, "x", 80.4, "53"]
    return {"groups": groups,
            "netContains": [{"net": n, "ip": i, "want": M.net_contains(n, i)} for n, i in nets],
            "normHost": [{"in": h, "want": M.norm_host(h)} for h in hosts],
            "normPort": [{"in": p, "want": M.norm_port(p)} for p in ports],
            "blocklist": blocklist_cases(),
            "launcher": launcher_cases()}


def blocklist_cases():
    """Feeds + lookups answered by the Linux monitor's own list_match."""
    import ipaddress
    from citadel.monitor import common as C
    feeds = [{"id": "firehol", "kind": "ip", "entries": ["5.188.10.0/23", "203.0.113.0/24", "2001:db8:bad::/48", "198.51.100.7"]},
             {"id": "spamhaus", "kind": "ip", "entries": ["203.0.113.128/25", "0.0.0.0/0"][:1]},
             {"id": "stevenblack", "kind": "domain", "entries": ["ads.example.com", "doubleclick.net", "tracker.io"]},
             {"id": "hagezi", "kind": "domain", "entries": ["example.com", "metrics.example.org"]}]
    nets = {}
    for f in feeds:
        if f["kind"] != "ip":
            continue
        by_len = {}
        for c in f["entries"]:
            n = ipaddress.ip_network(c, strict=False)
            by_len.setdefault((n.version, n.prefixlen), set()).add(int(n.network_address))
        nets[f["id"]] = by_len
    C.lists_state["nets"] = nets
    C.lists_state["domains"] = {f["id"]: set(f["entries"]) for f in feeds if f["kind"] == "domain"}
    C.ip_match_cache.clear()
    queries = [("", "5.188.11.9"), ("", "5.188.12.1"), ("", "203.0.113.200"), ("", "198.51.100.7"), ("", "198.51.100.8"),
               ("", "2001:db8:bad:1::5"), ("", "2001:db8:bee::1"), ("x.ads.example.com", "1.1.1.1"),
               ("ads.example.com.", ""), ("example.com", ""), ("www.example.com", ""), ("com", ""), ("tracker.io", "9.9.9.9"),
               ("metrics.example.org", ""), ("example.org", ""), ("Doubleclick.NET", ""), ("", ""), ("fine.example.net", "8.8.8.8")]
    return {"feeds": feeds, "queries": [{"host": h, "ip": ip, "want": C.list_match(h, ip)} for h, ip in queries]}


def launcher_cases():
    """Process trees and the launcher the monitor's origin() finds (macOS sets)."""
    from citadel.monitor import common as C, darwin  # noqa: F401  (darwin adds launchd, Terminal, …)
    rnd = random.Random(424242)
    progs = [("/usr/bin/curl", []), ("/usr/bin/git", ["fetch"]), ("/bin/zsh", []), ("/bin/bash", ["/Users/u/bin/sync.sh"]),
             ("/usr/bin/python3", ["-u", "/Users/u/tool.py"]), ("/usr/bin/python3", ["-c", "print(1)"]),
             ("/usr/local/bin/node", ["-m", "server"]), ("/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", []),
             ("/Applications/Ghostty.app/Contents/MacOS/ghostty", []), ("/usr/bin/env", ["python3"]), ("/usr/bin/sudo", ["curl"]),
             ("/Applications/Safari.app/Contents/MacOS/Safari", []), ("/usr/bin/osascript", ["/Users/u/run.scpt"]),
             ("/opt/homebrew/bin/python3.14", ["/Users/u/job.py"])]
    cases = []
    for t in range(80):
        n = rnd.randint(1, 6)
        table = {1: ("launchd", 0, "/sbin/launchd", ["/sbin/launchd"])}
        parent = 1
        pids = []
        for k in range(n):
            pid = 100 + t * 10 + k
            exe, extra = rnd.choice(progs)
            table[pid] = (os.path.basename(exe), parent, exe, [exe] + extra)
            pids.append(pid)
            parent = pid if rnd.random() < 0.8 else parent

        class Fake:
            @staticmethod
            def proc_stat(pid):
                r = table.get(pid)
                return (r[0], r[1], pid) if r else None

            @staticmethod
            def proc_exe(pid):
                return table.get(pid, ("", 0, "", []))[2]

            @staticmethod
            def proc_cmdline(pid):
                return table.get(pid, ("", 0, "", []))[3]
        C.use(Fake)
        C.origin_cache.clear()
        leaf = pids[-1]
        o = C.origin(leaf)
        v = (o or {}).get("via")
        cases.append({"procs": [{"pid": p, "comm": r[0], "ppid": r[1], "exe": r[2], "args": r[3]} for p, r in table.items()],
                      "pid": leaf, "want": v})
    return {"sets": {"shells": sorted(C.SHELLS), "interpreters": sorted(C.INTERPRETERS),
                     "terminals": sorted(C.TERMINALS), "managers": sorted(C.MANAGERS)}, "cases": cases}


def text():
    return json.dumps(build(), indent=None, separators=(",", ":"), sort_keys=True) + "\n"


if __name__ == "__main__":
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        f.write(text())
    print("wrote", OUT, os.path.getsize(OUT), "bytes")

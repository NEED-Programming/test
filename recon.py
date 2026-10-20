#!/usr/bin/env python3
"""
recon.py — IP-first external-recon orchestrator.

Chains ProjectDiscovery tooling + nmap into a resumable pipeline with one
normalized SQLite store, so stages read the store (not each other's stdout).

Pipeline:
    dnsx (PTR)  ─┐
    tlsx (certs)─┴─> recovered hostnames
    naabu       ───> open ports
    nmap        ───> service/version  (only on discovered open ports)
    httpx       ───> web triage       (IPs w/ open ports + recovered hostnames)

Design goals that actually matter for automation:
  * One store, JSON in — every tool emits structured output, nothing is scraped.
  * Idempotent + resumable — each stage records status per run; a crashed run
    resumes and skips completed stages.
  * Diffable — every row is stamped with a run_id; `diff` compares two runs.
  * Rate limits live in config, read once, applied everywhere.

Usage:
    python3 recon.py run   --scope ips.txt                 # full pipeline
    python3 recon.py run   --scope ips.txt --only naabu,nmap
    python3 recon.py run   --scope ips.txt --resume        # continue last run
    python3 recon.py diff                                  # last two runs
    python3 recon.py show  --run <id>                      # dump a run
    python3 recon.py runs                                  # list runs

Nothing here validates authorization or scope — that's on you and your SoW.
"""

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

# --------------------------------------------------------------------------- #
# Config — pull rate limits / knobs from here, not from scattered defaults.
# For a recurring engagement, move this into a YAML/TOML file and load it.
# --------------------------------------------------------------------------- #
CONFIG = {
    "db": "recon.db",
    "workdir": "recon_work",          # per-stage raw tool output lands here
    "naabu_rate": 1000,               # packets/sec — set from your RoE
    "naabu_ports": "top-1000",        # "top-1000" | "full" | "80,443,8080,..."
    "nmap_opts": ["-sV", "-sC", "-Pn"],
    "nmap_timing": "-T3",             # dial down for stealth / fragile targets
    "nmap_workers": 5,                # hosts scanned in parallel (subprocess only)
    "httpx_threads": 50,
    "httpx_rate": 150,                # requests/sec
    "nuclei_severity": "low,medium,high,critical",  # drop 'info' noise by default
    "nuclei_rate": 150,               # requests/sec — set from RoE
    "nuclei_concurrency": 25,         # parallel templates
    "nuclei_extra": [],               # e.g. ["-etags", "dos,intrusive"] to exclude
    "tools": {                        # override paths if not on $PATH
        "dnsx": "dnsx",
        "tlsx": "tlsx",
        "naabu": "naabu",
        "nmap": "nmap",
        "httpx": "httpx",
        "nuclei": "nuclei",
    },
}

STAGES = ["dnsx", "tlsx", "naabu", "nmap", "httpx", "nuclei"]


# --------------------------------------------------------------------------- #
# Store
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    scope_file  TEXT
);
CREATE TABLE IF NOT EXISTS stage_status (
    run_id  INTEGER NOT NULL,
    stage   TEXT NOT NULL,
    status  TEXT NOT NULL,           -- pending | running | done | error
    updated TEXT NOT NULL,
    PRIMARY KEY (run_id, stage)
);
CREATE TABLE IF NOT EXISTS hosts (
    ip         TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hostnames (
    ip       TEXT NOT NULL,
    hostname TEXT NOT NULL,
    source   TEXT NOT NULL,          -- ptr | cert
    run_id   INTEGER NOT NULL,
    PRIMARY KEY (ip, hostname, source, run_id)
);
CREATE TABLE IF NOT EXISTS ports (
    ip       TEXT NOT NULL,
    port     INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    run_id   INTEGER NOT NULL,
    PRIMARY KEY (ip, port, protocol, run_id)
);
CREATE TABLE IF NOT EXISTS services (
    ip       TEXT NOT NULL,
    port     INTEGER NOT NULL,
    service  TEXT,
    product  TEXT,
    version  TEXT,
    run_id   INTEGER NOT NULL,
    PRIMARY KEY (ip, port, run_id)
);
CREATE TABLE IF NOT EXISTS web (
    url     TEXT NOT NULL,
    ip      TEXT,
    port    INTEGER,
    status  INTEGER,
    title   TEXT,
    tech    TEXT,
    server  TEXT,
    run_id  INTEGER NOT NULL,
    PRIMARY KEY (url, run_id)
);
CREATE TABLE IF NOT EXISTS findings (
    matched_at  TEXT,
    template_id TEXT,
    name        TEXT,
    severity    TEXT,
    run_id      INTEGER NOT NULL,
    PRIMARY KEY (matched_at, template_id, run_id)
);
"""


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    # -- runs / stage tracking --------------------------------------------- #
    def new_run(self, scope_file):
        cur = self.db.execute(
            "INSERT INTO runs (started_at, scope_file) VALUES (?, ?)",
            (now(), scope_file),
        )
        rid = cur.lastrowid
        for s in STAGES:
            self.db.execute(
                "INSERT INTO stage_status (run_id, stage, status, updated) "
                "VALUES (?, ?, 'pending', ?)",
                (rid, s, now()),
            )
        self.db.commit()
        return rid

    def last_run(self):
        row = self.db.execute("SELECT id FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        return row["id"] if row else None

    def finish_run(self, rid):
        self.db.execute("UPDATE runs SET finished_at=? WHERE id=?", (now(), rid))
        self.db.commit()

    def stage(self, rid, stage):
        row = self.db.execute(
            "SELECT status FROM stage_status WHERE run_id=? AND stage=?",
            (rid, stage),
        ).fetchone()
        return row["status"] if row else "pending"

    def set_stage(self, rid, stage, status):
        self.db.execute(
            "UPDATE stage_status SET status=?, updated=? WHERE run_id=? AND stage=?",
            (status, now(), rid, stage),
        )
        self.db.commit()

    # -- upserts ----------------------------------------------------------- #
    def touch_host(self, ip):
        self.db.execute(
            "INSERT INTO hosts (ip, first_seen, last_seen) VALUES (?, ?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen",
            (ip, now(), now()),
        )

    def add_hostname(self, ip, hostname, source, rid):
        self.touch_host(ip)
        self.db.execute(
            "INSERT OR IGNORE INTO hostnames (ip, hostname, source, run_id) "
            "VALUES (?, ?, ?, ?)",
            (ip, hostname.strip().lower().rstrip("."), source, rid),
        )

    def add_port(self, ip, port, proto, rid):
        self.touch_host(ip)
        self.db.execute(
            "INSERT OR IGNORE INTO ports (ip, port, protocol, run_id) "
            "VALUES (?, ?, ?, ?)",
            (ip, int(port), proto, rid),
        )

    def add_service(self, ip, port, service, product, version, rid):
        self.db.execute(
            "INSERT OR REPLACE INTO services "
            "(ip, port, service, product, version, run_id) VALUES (?, ?, ?, ?, ?, ?)",
            (ip, int(port), service, product, version, rid),
        )

    def add_web(self, url, ip, port, status, title, tech, server, rid):
        self.db.execute(
            "INSERT OR REPLACE INTO web "
            "(url, ip, port, status, title, tech, server, run_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (url, ip, port, status, title, tech, server, rid),
        )

    def add_finding(self, matched_at, template_id, name, severity, rid):
        self.db.execute(
            "INSERT OR IGNORE INTO findings "
            "(matched_at, template_id, name, severity, run_id) "
            "VALUES (?, ?, ?, ?, ?)",
            (matched_at, template_id, name, severity, rid),
        )

    def commit(self):
        self.db.commit()

    # -- reads used to build the next stage's targets ---------------------- #
    def open_ports_by_host(self, rid):
        rows = self.db.execute(
            "SELECT ip, port FROM ports WHERE run_id=? ORDER BY ip, port", (rid,)
        ).fetchall()
        out = {}
        for r in rows:
            out.setdefault(r["ip"], []).append(r["port"])
        return out

    def hostnames_for_run(self, rid):
        rows = self.db.execute(
            "SELECT DISTINCT hostname FROM hostnames WHERE run_id=?", (rid,)
        ).fetchall()
        return [r["hostname"] for r in rows]

    def web_urls_for_run(self, rid):
        rows = self.db.execute(
            "SELECT DISTINCT url FROM web WHERE run_id=?", (rid,)
        ).fetchall()
        return [r["url"] for r in rows]


# --------------------------------------------------------------------------- #
# Tool execution helpers
# --------------------------------------------------------------------------- #
def have(tool):
    return shutil.which(CONFIG["tools"][tool]) is not None


def run_tool(argv, outfile=None):
    """Run a tool; if outfile given, stream stdout into it. Returns rc."""
    with open(outfile, "w") if outfile else subprocess.DEVNULL as fh:
        proc = subprocess.run(
            argv,
            stdout=fh if outfile else subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    if proc.returncode != 0 and proc.stderr:
        sys.stderr.write(f"[!] {argv[0]} stderr: {proc.stderr.strip()[:500]}\n")
    return proc.returncode


def jsonl(path):
    """Yield parsed objects from a JSON-lines file, tolerating junk lines."""
    if not os.path.exists(path):
        return
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def first(d, *keys, default=None):
    """First present, non-empty value among keys — tool schemas drift."""
    for k in keys:
        if k in d and d[k] not in (None, "", []):
            return d[k]
    return default


# --------------------------------------------------------------------------- #
# Stages. Each: build input from store -> run tool -> normalize into store.
# --------------------------------------------------------------------------- #
def stage_dnsx(store, rid, wd, scope):
    out = os.path.join(wd, "dnsx.json")
    run_tool([CONFIG["tools"]["dnsx"], "-l", scope, "-ptr", "-resp-only",
              "-j", "-silent"], out)
    n = 0
    for o in jsonl(out):
        ip = first(o, "host", "ip")
        ptrs = first(o, "ptr", "all", default=[])
        if isinstance(ptrs, str):
            ptrs = [ptrs]
        for name in ptrs or []:
            if ip and name:
                store.add_hostname(ip, name, "ptr", rid)
                n += 1
    store.commit()
    return f"{n} PTR hostnames"


def stage_tlsx(store, rid, wd, scope):
    out = os.path.join(wd, "tlsx.json")
    run_tool([CONFIG["tools"]["tlsx"], "-l", scope, "-cn", "-san",
              "-j", "-silent"], out)
    n = 0
    for o in jsonl(out):
        ip = first(o, "host", "ip")
        names = []
        cn = first(o, "subject_cn", "cn")
        if cn:
            names.append(cn)
        san = first(o, "subject_an", "san", default=[])
        if isinstance(san, str):
            san = [san]
        names.extend(san or [])
        for name in names:
            # skip wildcards/garbage that won't resolve to a scannable host
            name = name.lstrip("*.").strip()
            if ip and name and "." in name:
                store.add_hostname(ip, name, "cert", rid)
                n += 1
    store.commit()
    return f"{n} cert hostnames"


def stage_naabu(store, rid, wd, scope):
    out = os.path.join(wd, "naabu.json")
    argv = [CONFIG["tools"]["naabu"], "-l", scope,
            "-rate", str(CONFIG["naabu_rate"]), "-j", "-silent"]
    pc = CONFIG["naabu_ports"]
    if pc == "top-1000":
        argv += ["-top-ports", "1000"]
    elif pc == "full":
        argv += ["-p", "-"]
    else:
        argv += ["-p", pc]
    run_tool(argv, out)
    n = 0
    for o in jsonl(out):
        ip = first(o, "ip", "host")
        port = first(o, "port")
        proto = first(o, "protocol", default="tcp")
        if ip and port:
            store.add_port(ip, port, proto, rid)
            n += 1
    store.commit()
    return f"{n} open ports"


def stage_nmap(store, rid, wd, scope):
    """Targeted: each host gets only the ports naabu found open.

    Subprocess calls run in a thread pool (the slow, I/O-bound part), but XML
    parsing and DB writes stay on the main thread — a single sqlite3 connection
    is not safe to share across threads. So: fan out the scans, join, then
    parse sequentially.
    """
    targets = store.open_ports_by_host(rid)
    if not targets:
        return "no open ports to enrich"

    def scan(item):
        ip, ports = item
        plist = ",".join(str(p) for p in sorted(set(ports)))
        xml = os.path.join(wd, f"nmap_{ip.replace(':', '_')}.xml")
        argv = ([CONFIG["tools"]["nmap"]] + CONFIG["nmap_opts"]
                + [CONFIG["nmap_timing"], "-p", plist, "-oX", xml, ip])
        run_tool(argv)
        return xml

    with ThreadPoolExecutor(max_workers=CONFIG["nmap_workers"]) as pool:
        xmls = list(pool.map(scan, targets.items()))

    total = 0
    for xml in xmls:
        total += _parse_nmap_xml(store, rid, xml)
    store.commit()
    return f"{total} services identified"


def _parse_nmap_xml(store, rid, xml_path):
    if not os.path.exists(xml_path):
        return 0
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return 0
    n = 0
    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr") if addr is not None else None
        if not ip:
            continue
        for port in host.findall("./ports/port"):
            portid = port.get("portid")
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            if svc is not None:
                store.add_service(
                    ip, portid,
                    svc.get("name"), svc.get("product"), svc.get("version"),
                    rid,
                )
            else:
                store.add_service(ip, portid, None, None, None, rid)
            n += 1
    return n


def stage_httpx(store, rid, wd, scope):
    """Probe IP:port pairs that are open, plus every recovered hostname —
    a host may serve a default page by IP but the real app by vhost."""
    candidates = set()
    for ip, ports in store.open_ports_by_host(rid).items():
        for p in ports:
            candidates.add(f"{ip}:{p}")
    for hn in store.hostnames_for_run(rid):
        candidates.add(hn)
    if not candidates:
        return "no web candidates"

    infile = os.path.join(wd, "httpx_in.txt")
    with open(infile, "w") as fh:
        fh.write("\n".join(sorted(candidates)))

    out = os.path.join(wd, "httpx.json")
    run_tool([CONFIG["tools"]["httpx"], "-l", infile, "-j", "-silent",
              "-sc", "-title", "-tech-detect", "-server",
              "-threads", str(CONFIG["httpx_threads"]),
              "-rate-limit", str(CONFIG["httpx_rate"])], out)
    n = 0
    for o in jsonl(out):
        url = first(o, "url")
        if not url:
            continue
        tech = first(o, "tech", "technologies", default=[])
        if isinstance(tech, list):
            tech = ", ".join(tech)
        store.add_web(
            url,
            first(o, "host", "a", "ip"),
            first(o, "port"),
            first(o, "status_code", "status-code"),
            first(o, "title"),
            tech,
            first(o, "webserver", "server"),
            rid,
        )
        n += 1
    store.commit()
    return f"{n} web services"


def stage_nuclei(store, rid, wd, scope):
    """Templated vuln/misconfig checks against the web services httpx found.
    Severity-filtered by default to keep 'info' noise out of the store."""
    urls = store.web_urls_for_run(rid)
    if not urls:
        return "no web services to scan"

    infile = os.path.join(wd, "nuclei_in.txt")
    with open(infile, "w") as fh:
        fh.write("\n".join(sorted(urls)))

    out = os.path.join(wd, "nuclei.json")
    argv = [CONFIG["tools"]["nuclei"], "-l", infile, "-jsonl", "-silent",
            "-severity", CONFIG["nuclei_severity"],
            "-rate-limit", str(CONFIG["nuclei_rate"]),
            "-concurrency", str(CONFIG["nuclei_concurrency"]),
            "-o", out] + CONFIG["nuclei_extra"]
    run_tool(argv)

    n = 0
    for o in jsonl(out):
        info = o.get("info", {}) or {}
        store.add_finding(
            first(o, "matched-at", "matched_at", "host"),
            first(o, "template-id", "templateID", "template"),
            first(info, "name"),
            first(info, "severity", default="unknown"),
            rid,
        )
        n += 1
    store.commit()
    return f"{n} findings"


STAGE_FUNCS = {
    "dnsx": stage_dnsx,
    "tlsx": stage_tlsx,
    "naabu": stage_naabu,
    "nmap": stage_nmap,
    "httpx": stage_httpx,
    "nuclei": stage_nuclei,
}


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_run(args):
    scope = args.scope
    if not scope or not os.path.exists(scope):
        sys.exit(f"[x] scope file not found: {scope}")

    os.makedirs(CONFIG["workdir"], exist_ok=True)
    store = Store(CONFIG["db"])

    if args.resume:
        rid = store.last_run()
        if rid is None:
            sys.exit("[x] --resume given but no prior run exists")
        print(f"[*] resuming run {rid}")
    else:
        rid = store.new_run(scope)
        print(f"[*] started run {rid}")

    wd = os.path.join(CONFIG["workdir"], f"run_{rid}")
    os.makedirs(wd, exist_ok=True)

    selected = args.only.split(",") if args.only else STAGES
    for stage in STAGES:
        if stage not in selected:
            continue
        if store.stage(rid, stage) == "done":
            print(f"[=] {stage:6s} already done — skipping")
            continue
        if not have(stage):
            print(f"[!] {stage:6s} binary not found on PATH — skipping")
            store.set_stage(rid, stage, "error")
            continue

        print(f"[>] {stage:6s} running ...", flush=True)
        store.set_stage(rid, stage, "running")
        t0 = time.time()
        try:
            summary = STAGE_FUNCS[stage](store, rid, wd, scope)
            store.set_stage(rid, stage, "done")
            print(f"[+] {stage:6s} {summary}  ({time.time() - t0:.0f}s)")
        except Exception as e:  # noqa: BLE001 — don't let one stage kill the run
            store.set_stage(rid, stage, "error")
            print(f"[x] {stage:6s} errored: {e}")

    store.finish_run(rid)
    print(f"[*] run {rid} complete")


def cmd_runs(args):
    store = Store(CONFIG["db"])
    rows = store.db.execute(
        "SELECT id, started_at, finished_at, scope_file FROM runs ORDER BY id"
    ).fetchall()
    if not rows:
        print("no runs yet")
        return
    for r in rows:
        done = r["finished_at"] or "(unfinished)"
        print(f"run {r['id']:>3}  {r['started_at']}  ->  {done}  [{r['scope_file']}]")


def cmd_show(args):
    store = Store(CONFIG["db"])
    rid = args.run or store.last_run()
    if rid is None:
        sys.exit("no runs")
    print(f"=== run {rid} ===\n")
    for ip in [r["ip"] for r in store.db.execute(
            "SELECT DISTINCT ip FROM hosts ORDER BY ip")]:
        hns = store.db.execute(
            "SELECT hostname, source FROM hostnames WHERE ip=? AND run_id=?",
            (ip, rid)).fetchall()
        ports = store.db.execute(
            "SELECT p.port, s.service, s.product, s.version "
            "FROM ports p LEFT JOIN services s "
            "ON p.ip=s.ip AND p.port=s.port AND s.run_id=? "
            "WHERE p.ip=? AND p.run_id=? ORDER BY p.port",
            (rid, ip, rid)).fetchall()
        if not hns and not ports:
            continue
        print(ip)
        for h in hns:
            print(f"    name  {h['hostname']}  ({h['source']})")
        for p in ports:
            svc = " ".join(x for x in
                           (p["service"], p["product"], p["version"]) if x)
            print(f"    {p['port']:>5}/tcp  {svc or '?'}")
        print()

    findings = store.db.execute(
        "SELECT severity, name, matched_at, template_id FROM findings "
        "WHERE run_id=? ORDER BY CASE severity "
        "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
        "WHEN 'low' THEN 3 ELSE 4 END",
        (rid,)).fetchall()
    if findings:
        print("--- findings ---")
        for f in findings:
            sev = (f["severity"] or "?").upper()
            print(f"    [{sev:>8}] {f['name']}  @ {f['matched_at']}  "
                  f"({f['template_id']})")


def cmd_diff(args):
    store = Store(CONFIG["db"])
    ids = [r["id"] for r in store.db.execute(
        "SELECT id FROM runs ORDER BY id DESC LIMIT 2")]
    if len(ids) < 2:
        sys.exit("need at least two runs to diff")
    new, old = ids[0], ids[1]
    print(f"=== diff: run {old} -> run {new} ===\n")

    def portset(rid):
        return {(r["ip"], r["port"]) for r in store.db.execute(
            "SELECT ip, port FROM ports WHERE run_id=?", (rid,))}

    def nameset(rid):
        return {(r["ip"], r["hostname"]) for r in store.db.execute(
            "SELECT ip, hostname FROM hostnames WHERE run_id=?", (rid,))}

    def findingset(rid):
        return {(r["matched_at"], f"{r['name']} [{r['severity']}]")
                for r in store.db.execute(
            "SELECT matched_at, name, severity FROM findings WHERE run_id=?",
            (rid,))}

    op, np_ = portset(old), portset(new)
    on, nn = nameset(old), nameset(new)
    of_, nf_ = findingset(old), findingset(new)

    for label, added, removed in [
        ("PORT", np_ - op, op - np_),
        ("NAME", nn - on, on - nn),
        ("FIND", nf_ - of_, of_ - nf_),
    ]:
        for ip, val in sorted(added):
            print(f"  + {label}  {ip}  {val}")
        for ip, val in sorted(removed):
            print(f"  - {label}  {ip}  {val}")
    print("\n(+ appeared this run, - disappeared since last run)")


def main():
    ap = argparse.ArgumentParser(description="IP-first recon orchestrator")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the pipeline")
    r.add_argument("--scope", required=False, help="file of IPs/CIDRs")
    r.add_argument("--only", help="comma list of stages (dnsx,tlsx,naabu,nmap,httpx)")
    r.add_argument("--resume", action="store_true", help="continue the last run")
    r.set_defaults(func=cmd_run)

    sub.add_parser("runs", help="list runs").set_defaults(func=cmd_runs)

    s = sub.add_parser("show", help="dump a run's findings")
    s.add_argument("--run", type=int)
    s.set_defaults(func=cmd_show)

    sub.add_parser("diff", help="diff the last two runs").set_defaults(func=cmd_diff)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

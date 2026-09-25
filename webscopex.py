import os
import re
import ssl
import json
import time
import socket
import shutil
import sqlite3
import threading
import subprocess
import webbrowser
import argparse
import csv
import sys
import platform
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin, parse_qsl

import requests
import dns.resolver
from bs4 import BeautifulSoup
import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk

APP_NAME = "WebScopeX"
VERSION = "3.0.0"
UA = f"{APP_NAME}/{VERSION} (Authorized Security Assessment)"
DEFAULT_REPORT_ROOT = Path.home() / "WebScopeX-Reports"
DB_PATH = Path(__file__).resolve().parent / "webscopex_history.db"

COMMON_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 7001, 9000]
COMMON_PATHS = [
    "robots.txt", "sitemap.xml", ".well-known/security.txt", "admin/", "login", "signin",
    "api/", "api/v1/", "swagger/", "swagger.json", "openapi.json", "graphql", "docs/",
    "backup/", "uploads/", "server-status", "health", "status", "actuator/health", "manifest.json"
]
AUTH_HINTS = ("login", "signin", "sign-in", "register", "signup", "sign-up", "forgot", "reset", "password", "oauth", "sso", "mfa", "2fa", "logout")
WAF_SIGS = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "__cf_bm", "cloudflare"],
    "Akamai": ["akamai", "x-akamai"],
    "Imperva": ["incap_ses", "visid_incap", "x-iinfo", "imperva"],
    "AWS WAF / CloudFront": ["x-amz-cf-id", "x-amz-cf-pop", "cloudfront"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-cache", "sucuri"],
    "Fastly": ["fastly", "x-served-by", "x-cache-hits"],
}

MODULES = [
    ("dns", "DNS Records", "A, AAAA, MX, TXT, NS, CNAME"),
    ("subdomains", "Passive Subdomains", "Certificate Transparency discovery"),
    ("live", "Live HTTP/S Hosts", "Probe discovered web hosts"),
    ("ports", "Ports & Services", "Common web ports; Nmap when available"),
    ("headers", "Web Fingerprinting", "Headers, technologies, cookies, CORS, WAF"),
    ("tls", "TLS / Certificate", "Protocol, cipher and certificate metadata"),
    ("content", "Content Discovery", "robots, sitemap, security.txt, common endpoints"),
    ("crawl", "Crawler & Parameters", "Same-origin crawl and parameter discovery"),
    ("jsapi", "JavaScript / API / Auth", "Endpoints, APIs and authentication surfaces"),
    ("tools", "External Tool Status", "Detect optional installed integrations"),
]

PROFILES = {
    "Quick": {"dns", "subdomains", "live", "headers", "tls", "tools"},
    "Standard": {"dns", "subdomains", "live", "ports", "headers", "tls", "content", "crawl", "jsapi", "tools"},
    "Deep": {k for k, _, _ in MODULES},
    "Custom": set(),
}

TOOL_CATALOG = {
    "nmap": {"label": "Nmap", "kind": "winget", "package": "Insecure.Nmap", "description": "Port and service fingerprinting"},
    "subfinder": {"label": "Subfinder", "kind": "go", "module": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "description": "Passive subdomain discovery"},
    "httpx": {"label": "httpx", "kind": "go", "module": "github.com/projectdiscovery/httpx/cmd/httpx@latest", "description": "HTTP probing"},
    "naabu": {"label": "Naabu", "kind": "go", "module": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", "description": "Port discovery"},
    "katana": {"label": "Katana", "kind": "go", "module": "github.com/projectdiscovery/katana/cmd/katana@latest", "description": "Web crawling"},
    "nuclei": {"label": "Nuclei", "kind": "go", "module": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "description": "Template-based exposure checks"},
    "ffuf": {"label": "ffuf", "kind": "go", "module": "github.com/ffuf/ffuf/v2@latest", "description": "Content discovery"},
    "wafw00f": {"label": "wafw00f", "kind": "pip", "package": "wafw00f", "description": "WAF fingerprinting"},
    "whatweb": {"label": "WhatWeb", "kind": "manual", "description": "Technology fingerprinting; manual Windows setup recommended"},
}

def locate_tool(name):
    direct = shutil.which(name)
    if direct:
        return direct
    suffix = ".exe" if os.name == "nt" else ""
    candidates = [
        Path(sys.executable).resolve().parent / f"{name}{suffix}",
        Path.home() / "go" / "bin" / f"{name}{suffix}",
    ]
    if os.name == "nt":
        candidates += [Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Nmap" / "nmap.exe"] if name == "nmap" else []
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None

def _go_executable():
    direct = shutil.which("go")
    if direct:
        return direct
    if os.name == "nt":
        p = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Go" / "bin" / "go.exe"
        if p.exists():
            return str(p)
    return None

def install_external_tool(name, log_cb=print):
    spec = TOOL_CATALOG.get(name)
    if not spec:
        raise ValueError(f"Unknown tool: {name}")
    if locate_tool(name):
        log_cb(f"{name} is already installed.")
        return True
    kind = spec.get("kind")
    if kind == "manual":
        raise RuntimeError(f"{spec['label']} uses a manual Windows setup. See docs/TOOLS.md.")
    if kind == "winget":
        winget = shutil.which("winget")
        if not winget:
            raise RuntimeError("winget was not found. Install App Installer from Microsoft Store, then retry.")
        cmd = [winget, "install", "--id", spec["package"], "-e", "--accept-package-agreements", "--accept-source-agreements"]
    elif kind == "pip":
        cmd = [sys.executable, "-m", "pip", "install", "--upgrade", spec["package"]]
    elif kind == "go":
        go = _go_executable()
        if not go:
            winget = shutil.which("winget")
            if not winget:
                raise RuntimeError("Go is required and winget is unavailable. Install Go manually, then retry.")
            log_cb("Go is not installed. Installing Go first...")
            subprocess.run([winget, "install", "--id", "GoLang.Go", "-e", "--accept-package-agreements", "--accept-source-agreements"], check=False)
            go = _go_executable()
            if not go:
                raise RuntimeError("Go was installed but is not visible yet. Restart WebScopeX and click Install again.")
        cmd = [go, "install", spec["module"]]
    else:
        raise RuntimeError("Unsupported installer recipe")
    log_cb("Running: " + " ".join(str(x) for x in cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.stdout.strip(): log_cb(proc.stdout.strip())
    if proc.stderr.strip(): log_cb(proc.stderr.strip())
    if proc.returncode != 0:
        raise RuntimeError(f"Installer exited with code {proc.returncode}")
    log_cb(f"Installed {name}. Restart the app if PATH has not refreshed.")
    return True


@dataclass
class Finding:
    module: str
    item: str
    details: str
    severity: str = "info"
    timestamp: str = ""


class HistoryDB:
    def __init__(self, path=DB_PATH):
        self.path = Path(path)
        self._init()

    def _connect(self):
        return sqlite3.connect(self.path)

    def _init(self):
        with self._connect() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS scans(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    profile TEXT,
                    status TEXT,
                    report_html TEXT,
                    report_json TEXT,
                    findings_count INTEGER DEFAULT 0,
                    summary_json TEXT DEFAULT '{}'
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS workspaces(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    target TEXT NOT NULL,
                    scope_root TEXT NOT NULL,
                    notes TEXT DEFAULT '',
                    created_at TEXT NOT NULL
                )
            """)

    def start_scan(self, target, profile):
        with self._connect() as con:
            cur = con.execute(
                "INSERT INTO scans(target, started_at, profile, status) VALUES(?,?,?,?)",
                (target, datetime.now().isoformat(timespec="seconds"), profile, "running")
            )
            return cur.lastrowid

    def finish_scan(self, scan_id, status, report_html="", report_json="", count=0, summary=None):
        with self._connect() as con:
            con.execute(
                "UPDATE scans SET finished_at=?, status=?, report_html=?, report_json=?, findings_count=?, summary_json=? WHERE id=?",
                (datetime.now().isoformat(timespec="seconds"), status, report_html, report_json, int(count), json.dumps(summary or {}), scan_id)
            )

    def recent(self, limit=50):
        with self._connect() as con:
            con.row_factory = sqlite3.Row
            return [dict(r) for r in con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]

    def previous_completed(self, target, exclude_id=None):
        with self._connect() as con:
            con.row_factory = sqlite3.Row
            sql = "SELECT * FROM scans WHERE target=? AND status='completed'"
            args = [target]
            if exclude_id:
                sql += " AND id<>?"
                args.append(exclude_id)
            sql += " ORDER BY id DESC LIMIT 1"
            row = con.execute(sql, args).fetchone()
            return dict(row) if row else None

    def save_workspace(self, name, target, scope_root, notes=""):
        with self._connect() as con:
            con.execute("""
                INSERT INTO workspaces(name,target,scope_root,notes,created_at) VALUES(?,?,?,?,?)
                ON CONFLICT(name) DO UPDATE SET target=excluded.target, scope_root=excluded.scope_root, notes=excluded.notes
            """, (name, target, scope_root, notes, datetime.now().isoformat(timespec="seconds")))

    def list_workspaces(self):
        with self._connect() as con:
            con.row_factory = sqlite3.Row
            return [dict(r) for r in con.execute("SELECT * FROM workspaces ORDER BY name COLLATE NOCASE").fetchall()]

    def delete_workspace(self, workspace_id):
        with self._connect() as con:
            con.execute("DELETE FROM workspaces WHERE id=?", (workspace_id,))

    def get_scan(self, scan_id):
        with self._connect() as con:
            con.row_factory = sqlite3.Row
            r = con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            return dict(r) if r else None


class Scanner:
    def __init__(self, target, outdir, log_cb, progress_cb, result_cb, status_cb, modules, stop_event=None, scope_root=None, rate_delay=0.05):
        self.target_input = target.strip()
        self.domain = self.normalize_domain(self.target_input)
        self.scope_root = self.normalize_domain(scope_root or self.domain)
        self.base_urls = []
        self.outdir = Path(outdir)
        self.log = log_cb
        self.progress = progress_cb
        self.result_cb = result_cb
        self.status_cb = status_cb
        self.modules = modules
        self.stop_event = stop_event or threading.Event()
        self.rate_delay = max(0.0, float(rate_delay))
        self.findings = []
        self.discovered_urls = set()
        self.js_urls = set()
        self.host_ips = defaultdict(set)
        self.host_services = defaultdict(dict)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.timeout = 7

    @staticmethod
    def normalize_domain(value):
        value = value.strip()
        if "://" in value:
            value = urlparse(value).hostname or value
        value = value.split("/")[0].split(":")[0].strip(". ")
        if not re.fullmatch(r"[A-Za-z0-9.-]+", value):
            raise ValueError("Enter a valid domain/hostname only, e.g. example.com")
        return value.lower()

    def in_scope_host(self, host):
        if not host:
            return False
        host = host.lower().strip(".")
        return host == self.scope_root or host.endswith("." + self.scope_root)

    def stopped(self):
        return self.stop_event.is_set()

    def add(self, module, item, details, severity="info"):
        f = Finding(module, str(item), str(details), severity, datetime.now().strftime("%H:%M:%S"))
        self.findings.append(f)
        self.log(f"[{module}] {item}: {details}")
        self.result_cb(f)

    def request(self, url, method="GET", **kwargs):
        if self.stopped():
            return None
        host = urlparse(url).hostname
        if host and not self.in_scope_host(host):
            return None
        if self.rate_delay:
            time.sleep(self.rate_delay)
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", True)
        try:
            r = self.session.request(method, url, **kwargs)
            # Prevent redirected traversal outside declared scope.
            final_host = urlparse(r.url).hostname
            if final_host and not self.in_scope_host(final_host):
                return None
            return r
        except requests.exceptions.SSLError:
            kwargs["verify"] = False
            try:
                r = self.session.request(method, url, **kwargs)
                final_host = urlparse(r.url).hostname
                return r if not final_host or self.in_scope_host(final_host) else None
            except requests.RequestException:
                return None
        except requests.RequestException:
            return None

    def dns_enum(self):
        self.status_cb("DNS enumeration")
        for rtype in ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]:
            if self.stopped():
                return
            try:
                ans = dns.resolver.resolve(self.domain, rtype, lifetime=5)
                for v in [str(x).strip() for x in ans]:
                    self.add("DNS", rtype, v)
                    if rtype in ("A", "AAAA"):
                        self.host_ips[self.domain].add(v)
                        self.add("Asset IP", self.domain, v)
            except Exception:
                pass

    def passive_subdomains(self):
        self.status_cb("Passive subdomain discovery")
        try:
            r = self.session.get("https://crt.sh/", params={"q": f"%.{self.domain}", "output": "json"}, timeout=12)
            if r.ok:
                names = set()
                for row in r.json():
                    for n in str(row.get("name_value", "")).splitlines():
                        n = n.strip().lower().lstrip("*.")
                        if self.in_scope_host(n):
                            names.add(n)
                for n in sorted(names):
                    if self.stopped():
                        break
                    self.add("Subdomains", "Passive", n)
                return sorted(names)
        except Exception as e:
            self.add("Subdomains", "Passive source unavailable", e, "low")
        return []

    def live_hosts(self, hostnames=None):
        self.status_cb("Live HTTP/S discovery")
        hosts = hostnames or [self.domain]
        live = []
        for host in hosts[:250]:
            if self.stopped():
                break
            if not self.in_scope_host(host):
                continue
            try:
                for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
                    ip = sockaddr[0]
                    if ip not in self.host_ips[host]:
                        self.host_ips[host].add(ip)
                        self.add("Asset IP", host, ip)
            except Exception:
                pass
            for scheme in ("https", "http"):
                u = f"{scheme}://{host}/"
                r = self.request(u)
                if r is not None:
                    final = r.url
                    self.add("Live Hosts", host, f"{r.status_code} {final}")
                    live.append(final.rstrip("/"))
                    break
        self.base_urls = list(dict.fromkeys(live)) or [f"https://{self.domain}", f"http://{self.domain}"]
        return self.base_urls

    def port_scan(self):
        self.status_cb("Port and service enumeration")
        if self.stopped():
            return
        hosts = []
        for base in self.base_urls:
            h = urlparse(base).hostname
            if h and self.in_scope_host(h) and h not in hosts:
                hosts.append(h)
        if self.domain not in hosts:
            hosts.insert(0, self.domain)
        hosts = hosts[:30]
        nmap = locate_tool("nmap")
        if nmap:
            for host in hosts:
                if self.stopped():
                    break
                try:
                    cmd = [nmap, "-Pn", "-sV", "--version-light", "-oX", "-", "-p", ",".join(map(str, COMMON_PORTS)), host]
                    p = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
                    if not p.stdout.strip():
                        continue
                    root = ET.fromstring(p.stdout)
                    for hnode in root.findall("host"):
                        addr = hnode.find("address")
                        ip = addr.get("addr") if addr is not None else ""
                        if ip:
                            self.host_ips[host].add(ip)
                            self.add("Asset IP", host, ip)
                        for pnode in hnode.findall("./ports/port"):
                            state = pnode.find("state")
                            if state is None or state.get("state") != "open":
                                continue
                            portid = pnode.get("portid", "")
                            service = pnode.find("service")
                            svc = service.get("name", "unknown") if service is not None else "unknown"
                            product = service.get("product", "") if service is not None else ""
                            version = service.get("version", "") if service is not None else ""
                            extra = " ".join(x for x in (product, version) if x).strip()
                            detail = f"open | service={svc}" + (f" | product={extra}" if extra else "")
                            self.host_services[host][portid] = {"service": svc, "product": extra}
                            self.add("Ports", f"{host}:{portid}", detail)
                    continue
                except Exception as e:
                    self.add("Ports", f"{host} nmap", f"Nmap parsing failed: {e}", "low")
        else:
            for host in hosts:
                if self.stopped():
                    break
                try:
                    ip = socket.gethostbyname(host)
                    self.host_ips[host].add(ip)
                    for port in COMMON_PORTS:
                        if self.stopped():
                            break
                        sock = socket.socket()
                        sock.settimeout(0.6)
                        try:
                            if sock.connect_ex((ip, port)) == 0:
                                try:
                                    svc = socket.getservbyport(port, "tcp")
                                except Exception:
                                    svc = "unknown"
                                self.host_services[host][str(port)] = {"service": svc, "product": ""}
                                self.add("Ports", f"{host}:{port}", f"open | service={svc}")
                        finally:
                            sock.close()
                except Exception as e:
                    self.add("Ports", f"{host} fallback", str(e), "low")

    def headers_tech_waf_cookies_cors(self):
        self.status_cb("Web fingerprinting")
        for base in self.base_urls[:20]:
            if self.stopped():
                break
            r = self.request(base + "/")
            if r is None:
                continue
            headers = {k.lower(): v for k, v in r.headers.items()}
            self.add("Headers", base, json.dumps(dict(r.headers), ensure_ascii=False))
            server = headers.get("server")
            powered = headers.get("x-powered-by")
            if server:
                self.add("Technology", "Server", server)
            if powered:
                self.add("Technology", "X-Powered-By", powered)
            html = r.text[:250000]
            checks = {
                "WordPress": ["wp-content/", "wp-includes/"], "Drupal": ["drupalSettings", "/sites/default/"],
                "React": ["data-reactroot", "__REACT_DEVTOOLS_GLOBAL_HOOK__"], "Next.js": ["__NEXT_DATA__", "/_next/"],
                "Vue": ["__VUE__", "data-v-"], "Angular": ["ng-version", "ng-app"],
                "Bootstrap": ["bootstrap.min.css", "bootstrap.bundle"], "jQuery": ["jquery.min.js", "jquery-"]
            }
            low = html.lower()
            tech = [name for name, sigs in checks.items() if any(s.lower() in low for s in sigs)]
            if tech:
                self.add("Technology", base, ", ".join(sorted(set(tech))))
            cookies = r.headers.get("Set-Cookie")
            if cookies:
                self.add("Cookies", base, cookies[:4000])
            cr = self.request(base + "/", headers={"Origin": "https://example.invalid"})
            if cr:
                acao = cr.headers.get("Access-Control-Allow-Origin", "")
                acc = cr.headers.get("Access-Control-Allow-Credentials", "")
                if acao:
                    self.add("CORS", base, f"ACAO={acao}; Credentials={acc or 'not set'}")
            blob = " ".join([f"{k}:{v}" for k, v in headers.items()]).lower() + " " + low[:20000]
            for waf, sigs in WAF_SIGS.items():
                if any(sig in blob for sig in sigs):
                    self.add("WAF", base, waf)

    def tls_enum(self):
        self.status_cb("TLS / certificate enumeration")
        if self.stopped():
            return
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=6) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.domain) as ss:
                    cert = ss.getpeercert()
                    self.add("TLS", "Protocol", ss.version())
                    self.add("TLS", "Cipher", ss.cipher())
                    self.add("TLS", "Certificate", json.dumps(cert, default=str))
        except Exception as e:
            self.add("TLS", "HTTPS/TLS check", e, "low")

    def well_known_paths(self):
        self.status_cb("Content discovery")
        for base in self.base_urls[:10]:
            for p in COMMON_PATHS:
                if self.stopped():
                    return
                u = urljoin(base.rstrip("/") + "/", p)
                r = self.request(u)
                if r is not None and r.status_code < 400:
                    ctype = r.headers.get("Content-Type", "")
                    self.add("Content Discovery", f"{r.status_code} {u}", ctype)
                    if p in ("robots.txt", "sitemap.xml", ".well-known/security.txt"):
                        self.add("Public Files", u, r.text[:5000])

    def crawl(self):
        self.status_cb("Same-origin crawl")
        for base in self.base_urls[:5]:
            parsed = urlparse(base)
            host = parsed.hostname
            q = [(base + "/", 0)]
            seen = set()
            while q and len(seen) < 250 and not self.stopped():
                u, depth = q.pop(0)
                if u in seen or depth > 2:
                    continue
                seen.add(u)
                r = self.request(u)
                if r is None or "text/html" not in r.headers.get("Content-Type", ""):
                    continue
                self.discovered_urls.add(r.url)
                soup = BeautifulSoup(r.text, "html.parser")
                for tag, attr in [("a", "href"), ("form", "action"), ("script", "src")]:
                    for el in soup.find_all(tag):
                        val = el.get(attr)
                        if not val:
                            continue
                        nu = urljoin(r.url, val).split("#")[0]
                        np = urlparse(nu)
                        if np.hostname != host or not self.in_scope_host(np.hostname):
                            continue
                        if tag == "script" and np.path.lower().endswith(".js"):
                            self.js_urls.add(nu)
                        if nu not in seen and depth < 2:
                            q.append((nu, depth + 1))
                for inp in soup.find_all(["input", "textarea", "select"]):
                    name = inp.get("name") or inp.get("id")
                    if name:
                        self.add("Parameters", r.url, name)
            self.add("Crawler", base, f"{len(seen)} pages/requests visited")
        for u in sorted(self.discovered_urls):
            self.add("URLs", "Discovered", u)

    def js_api_auth(self):
        self.status_cb("JavaScript / API / auth mapping")
        endpoint_re = re.compile(r'''["']((?:/|https?://)[A-Za-z0-9_\-./?=&%:{}]+)["']''')
        for js in list(self.js_urls)[:80]:
            if self.stopped():
                return
            r = self.request(js)
            if not r or len(r.content) > 2_000_000:
                continue
            for m in endpoint_re.findall(r.text):
                if any(x in m.lower() for x in ("api", "graphql", "auth", "login", "user", "admin", "token", "oauth")):
                    self.add("JavaScript", js, m[:500])
        candidates = set(self.discovered_urls)
        for base in self.base_urls[:10]:
            for p in ("api", "api/v1", "graphql", "swagger", "swagger.json", "openapi.json", "docs"):
                candidates.add(urljoin(base.rstrip("/") + "/", p))
        for u in sorted(candidates):
            if self.stopped():
                return
            if not self.in_scope_host(urlparse(u).hostname):
                continue
            low = u.lower()
            if any(x in low for x in ("/api", "graphql", "swagger", "openapi")):
                r = self.request(u)
                if r is not None and r.status_code < 400:
                    self.add("API", str(r.status_code), u)
            if any(x in low for x in AUTH_HINTS):
                self.add("Authentication", "Surface", u)
            for k, _ in parse_qsl(urlparse(u).query, keep_blank_values=True):
                self.add("Parameters", u, k)

    def external_tool_status(self):
        self.status_cb("External integration status")
        for name in ["nmap", "subfinder", "httpx", "ffuf", "nuclei", "whatweb", "wafw00f", "katana", "naabu"]:
            self.add("Tool Status", name, locate_tool(name) or "not found")

    def asset_graph(self):
        nodes = {}
        edges = []
        def node(node_id, kind, label=None, **meta):
            entry = {"id": node_id, "kind": kind, "label": label or node_id}
            entry.update(meta)
            nodes[node_id] = entry
        def edge(a, b, relation):
            if a and b:
                edges.append((a, b, relation))
        root = self.domain
        node(root, "domain")
        known_hosts = {root}
        for f in self.findings:
            if f.module == "Subdomains":
                sub = f.details.strip()
                if sub and self.in_scope_host(sub):
                    known_hosts.add(sub); node(sub, "subdomain"); edge(root, sub, "subdomain")
            elif f.module == "Live Hosts":
                host = f.item.strip()
                if host:
                    known_hosts.add(host); node(host, "host"); edge(root if host == root else root, host, "live-host")
            elif f.module == "Asset IP":
                host = f.item.strip(); ip = f.details.strip()
                if host and ip:
                    known_hosts.add(host); node(host, "host" if host == root else "subdomain"); node(f"ip:{ip}", "ip", ip); edge(host, f"ip:{ip}", "resolves-to")
            elif f.module == "Ports":
                m = re.match(r"(.+):(\d+)$", f.item.strip())
                if m:
                    host, port = m.group(1), m.group(2)
                    known_hosts.add(host); node(host, "host" if host == root else "subdomain")
                    pid = f"port:{host}:{port}"; node(pid, "port", f"{port}/tcp"); edge(host, pid, "exposes")
                    sm = re.search(r"service=([^|]+)", f.details)
                    if sm:
                        svc = sm.group(1).strip(); sid = f"service:{host}:{port}:{svc}"; node(sid, "service", svc); edge(pid, sid, "runs")
            elif f.module in ("API", "URLs", "Content Discovery", "Authentication", "JavaScript"):
                candidates = [str(f.item), str(f.details)]
                url = next((x for x in candidates if x.startswith("http://") or x.startswith("https://")), "")
                if url:
                    host = urlparse(url).hostname or root
                    if self.in_scope_host(host):
                        known_hosts.add(host); node(host, "host" if host == root else "subdomain")
                        uid = f"endpoint:{url[:500]}"; node(uid, "endpoint", url[:500], module=f.module); edge(host, uid, f.module.lower())
            elif f.module == "Technology":
                host = urlparse(f.item).hostname if str(f.item).startswith("http") else root
                host = host or root
                tid = f"tech:{host}:{f.details}"; node(tid, "technology", f.details[:100]); edge(host, tid, "technology")
        seen = set(); dedup = []
        for e in edges:
            if e not in seen:
                seen.add(e); dedup.append(e)
        return {"nodes": list(nodes.values()), "edges": [{"source": a, "target": b, "relation": r} for a,b,r in dedup]}

    @staticmethod
    def compare_reports(previous_path, current_findings):
        if not previous_path or not os.path.exists(previous_path):
            return {"added": [], "removed": [], "unchanged": 0, "previous_available": False, "by_module": {}}
        try:
            old = json.loads(Path(previous_path).read_text(encoding="utf-8"))
            oldset = {(x.get("module",""), x.get("item",""), x.get("details",""), x.get("severity","info")) for x in old.get("findings", [])}
            newset = {(f.module, f.item, f.details, f.severity) for f in current_findings}
            added = sorted(newset - oldset)
            removed = sorted(oldset - newset)
            by_module = defaultdict(lambda: {"added": 0, "removed": 0})
            for m, *_ in added: by_module[m]["added"] += 1
            for m, *_ in removed: by_module[m]["removed"] += 1
            return {"added": added, "removed": removed, "unchanged": len(oldset & newset), "previous_available": True, "by_module": dict(by_module)}
        except Exception:
            return {"added": [], "removed": [], "unchanged": 0, "previous_available": False, "by_module": {}}

    def summary(self):
        counts = Counter(f.module for f in self.findings)
        return {
            "subdomains": counts.get("Subdomains", 0),
            "live_hosts": counts.get("Live Hosts", 0),
            "ports": counts.get("Ports", 0),
            "apis": counts.get("API", 0),
            "urls": counts.get("URLs", 0),
            "technologies": counts.get("Technology", 0),
            "total": len(self.findings),
        }

    def save_report(self):
        self.outdir.mkdir(parents=True, exist_ok=True)
        generated = datetime.now().isoformat(timespec="seconds")
        graph = self.asset_graph()
        data = {
            "tool": APP_NAME,
            "version": VERSION,
            "target": self.domain,
            "scope_root": self.scope_root,
            "generated_at": generated,
            "summary": self.summary(),
            "graph": graph,
            "findings": [asdict(f) for f in self.findings],
        }
        jpath = self.outdir / "report.json"
        jpath.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        (self.outdir / "graph.json").write_text(json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8")

        modules = sorted(set(f.module for f in self.findings))
        rows = "".join(
            f"<tr data-module='{esc(f.module)}' data-severity='{esc(f.severity)}'><td>{esc(f.timestamp)}</td><td><span class='pill'>{esc(f.module)}</span></td><td>{esc(f.item)}</td><td><pre>{esc(f.details)}</pre></td><td><span class='sev {esc(f.severity)}'>{esc(f.severity.upper())}</span></td></tr>"
            for f in self.findings
        )
        module_options = "".join(f"<option value='{esc(m)}'>{esc(m)}</option>" for m in modules)
        graph_rows = "".join(
            f"<tr><td>{esc(n.get('kind',''))}</td><td>{esc(n.get('label',''))}</td><td>{esc(n.get('id',''))}</td></tr>"
            for n in graph.get("nodes", [])[:1000]
        )
        s = self.summary()
        html = f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{APP_NAME} report - {esc(self.domain)}</title>
<style>
:root{{--bg:#071018;--panel:#0b1623;--panel2:#0f1b2a;--line:#20354b;--text:#dbeafe;--muted:#94a3b8;--cyan:#67e8f9;--green:#6ee7b7;--amber:#fbbf24;--red:#fca5a5}}
*{{box-sizing:border-box}}body{{font-family:Inter,Segoe UI,Arial,sans-serif;margin:0;background:linear-gradient(180deg,#061019,#08131f);color:var(--text)}}
.wrap{{max-width:1500px;margin:auto;padding:32px}}.hero{{display:flex;justify-content:space-between;gap:20px;align-items:flex-end;flex-wrap:wrap}}
h1{{margin:0;color:var(--cyan);font-size:32px}}.meta{{color:var(--muted);margin-top:8px;line-height:1.7}}.badge{{padding:8px 12px;border:1px solid #1d4e63;border-radius:999px;color:var(--cyan);background:#082230}}
.cards{{display:grid;grid-template-columns:repeat(6,minmax(130px,1fr));gap:12px;margin:24px 0}}.card{{background:var(--panel2);border:1px solid var(--line);border-radius:14px;padding:18px;box-shadow:0 12px 35px #0003}}
.num{{font-size:30px;font-weight:800;color:#fff}}.lbl{{font-size:12px;color:var(--muted);margin-top:4px}}
.section{{background:var(--panel);border:1px solid var(--line);border-radius:14px;margin:16px 0;padding:18px}}.section h2{{margin:0 0 14px;font-size:18px}}
.filters{{display:grid;grid-template-columns:minmax(240px,1fr) 220px 160px;gap:10px;margin-bottom:14px}}input,select{{background:#06111b;border:1px solid #21435f;border-radius:9px;color:var(--text);padding:11px 12px;outline:none}}
.tablewrap{{overflow:auto;max-height:680px;border-radius:10px;border:1px solid #183249}}table{{border-collapse:collapse;width:100%;background:#08131f}}td,th{{border-bottom:1px solid #183249;padding:10px;vertical-align:top;text-align:left}}th{{background:#10243a;color:var(--cyan);position:sticky;top:0;z-index:2}}pre{{white-space:pre-wrap;word-break:break-word;margin:0;color:#cbd5e1;font-family:Consolas,monospace}}
.pill{{display:inline-block;border:1px solid #1f4660;border-radius:999px;padding:3px 8px;color:#bae6fd;background:#0b2638;font-size:12px}}.sev{{font-size:11px;font-weight:700;border-radius:999px;padding:4px 7px}}.sev.info{{background:#0b2e40;color:#7dd3fc}}.sev.low{{background:#3f320b;color:#fde68a}}.sev.medium{{background:#4a2a0a;color:#fdba74}}.sev.high{{background:#471515;color:#fca5a5}}
.small{{font-size:12px;color:var(--muted)}}@media(max-width:1000px){{.cards{{grid-template-columns:repeat(3,1fr)}}.filters{{grid-template-columns:1fr}}}}@media(max-width:620px){{.cards{{grid-template-columns:repeat(2,1fr)}}.wrap{{padding:18px}}}}
</style></head><body><div class='wrap'>
<div class='hero'><div><h1>{APP_NAME} <span style='color:#64748b;font-size:16px'>v{VERSION}</span></h1><div class='meta'><b>Target:</b> {esc(self.domain)} &nbsp; - &nbsp; <b>Scope:</b> {esc(self.scope_root)} and subdomains<br><b>Generated:</b> {esc(generated)}</div></div><div class='badge'>Authorized reconnaissance report</div></div>
<div class='cards'><div class='card'><div class='num'>{s['subdomains']}</div><div class='lbl'>Subdomains</div></div><div class='card'><div class='num'>{s['live_hosts']}</div><div class='lbl'>Live Hosts</div></div><div class='card'><div class='num'>{s['ports']}</div><div class='lbl'>Port / Service Findings</div></div><div class='card'><div class='num'>{s['apis']}</div><div class='lbl'>APIs</div></div><div class='card'><div class='num'>{s['urls']}</div><div class='lbl'>URLs</div></div><div class='card'><div class='num'>{s['total']}</div><div class='lbl'>Total Evidence</div></div></div>
<div class='section'><h2>Recon graph inventory</h2><div class='small'>Graph export: <code>graph.json</code>. Relations include domain -&gt; subdomain -&gt; IP -&gt; port -&gt; service and host -&gt; endpoint.</div><div class='tablewrap' style='max-height:320px;margin-top:12px'><table><thead><tr><th>Type</th><th>Label</th><th>Node ID</th></tr></thead><tbody>{graph_rows}</tbody></table></div></div>
<div class='section'><h2>Findings &amp; evidence</h2><div class='filters'><input id='q' placeholder='Search module, item or details...' oninput='filterRows()'><select id='m' onchange='filterRows()'><option value=''>All modules</option>{module_options}</select><select id='sev' onchange='filterRows()'><option value=''>All severities</option><option>info</option><option>low</option><option>medium</option><option>high</option></select></div><div class='tablewrap'><table id='findings'><thead><tr><th>Time</th><th>Module</th><th>Item</th><th>Details</th><th>Severity</th></tr></thead><tbody>{rows}</tbody></table></div></div>
<div class='small'>Generated locally by {APP_NAME}. Review evidence manually before making security decisions.</div>
</div><script>
function filterRows(){{const q=document.getElementById('q').value.toLowerCase();const m=document.getElementById('m').value;const s=document.getElementById('sev').value;document.querySelectorAll('#findings tbody tr').forEach(r=>{{const okq=!q||r.innerText.toLowerCase().includes(q);const okm=!m||r.dataset.module===m;const oks=!s||r.dataset.severity===s;r.style.display=(okq&&okm&&oks)?'':'none';}});}}
</script></body></html>"""
        hpath = self.outdir / "report.html"
        hpath.write_text(html, encoding="utf-8")
        return str(hpath), str(jpath)

    def run(self):
        subdomains = []
        keys = ["dns", "subdomains", "live", "ports", "headers", "tls", "content", "crawl", "jsapi", "tools"]
        total = max(1, sum(bool(self.modules.get(k)) for k in keys))
        done = 0

        def step(key, fn):
            nonlocal done
            if self.modules.get(key) and not self.stopped():
                fn()
                done += 1
                self.progress(done / total * 100)

        step("dns", self.dns_enum)
        if self.modules.get("subdomains") and not self.stopped():
            subdomains = self.passive_subdomains()
            done += 1
            self.progress(done / total * 100)
        if self.modules.get("live") and not self.stopped():
            self.live_hosts([self.domain] + [x for x in subdomains if x != self.domain])
            done += 1
            self.progress(done / total * 100)
        else:
            self.live_hosts([self.domain])
        step("ports", self.port_scan)
        step("headers", self.headers_tech_waf_cookies_cors)
        step("tls", self.tls_enum)
        step("content", self.well_known_paths)
        step("crawl", self.crawl)
        step("jsapi", self.js_api_auth)
        step("tools", self.external_tool_status)

        hp, jp = self.save_report()
        self.progress(100 if not self.stopped() else min(99, done / total * 100))
        self.status_cb("Stopped" if self.stopped() else "Completed")
        self.log(f"REPORT HTML: {hp}")
        self.log(f"REPORT JSON: {jp}")
        return hp, jp, self.summary()


def esc(s):
    import html
    return html.escape(str(s))


class WebScopeXApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.title(f"{APP_NAME} v{VERSION}")
        self.geometry("1420x860")
        self.minsize(1180, 720)
        self.db = HistoryDB()
        self.stop_event = threading.Event()
        self.scan_thread = None
        self.scan_id = None
        self.last_report = None
        self.last_json = None
        self.current_findings = []
        self.module_vars = {}
        self.nav_buttons = {}
        self.pages = {}
        self.metric_labels = {}
        self.current_profile = ctk.StringVar(value="Standard")
        self.status_text = ctk.StringVar(value="READY")
        self.current_module = ctk.StringVar(value="Idle")
        self._build_shell()
        self._show_page("Dashboard")
        self.apply_profile("Standard")
        self.refresh_history()
        self.refresh_workspaces()
        self.refresh_tool_status()

    def _build_shell(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color="#07111d")
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        brand = ctk.CTkLabel(self.sidebar, text="WEBSCOPEX", font=ctk.CTkFont(size=26, weight="bold"), text_color="#67e8f9")
        brand.pack(anchor="w", padx=22, pady=(24, 0))
        ctk.CTkLabel(self.sidebar, text="MAP  •  ENUMERATE  •  UNDERSTAND", font=ctk.CTkFont(size=11), text_color="#64748b").pack(anchor="w", padx=22, pady=(0, 24))

        for name in ["Dashboard", "Workspaces", "Target & Scope", "Modules", "Findings", "Recon Graph", "Delta Scan", "History", "Tool Status", "Settings"]:
            b = ctk.CTkButton(
                self.sidebar, text=name, anchor="w", height=42, corner_radius=8,
                fg_color="transparent", hover_color="#10243a", text_color="#cbd5e1",
                command=lambda n=name: self._show_page(n)
            )
            b.pack(fill="x", padx=12, pady=3)
            self.nav_buttons[name] = b

        ctk.CTkLabel(self.sidebar, text="AUTHORIZED USE ONLY", font=ctk.CTkFont(size=10, weight="bold"), text_color="#f59e0b").pack(side="bottom", pady=(0, 8))
        ctk.CTkLabel(self.sidebar, text="Enumeration • Evidence • Reporting", font=ctk.CTkFont(size=10), text_color="#475569").pack(side="bottom", pady=(0, 2))

        self.content = ctk.CTkFrame(self, corner_radius=0, fg_color="#08131f")
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(1, weight=1)

        self.topbar = ctk.CTkFrame(self.content, height=66, corner_radius=0, fg_color="#0b1826")
        self.topbar.grid(row=0, column=0, sticky="ew")
        self.topbar.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(self.topbar, text="Web Enumeration Workspace", font=ctk.CTkFont(size=18, weight="bold")).grid(row=0, column=0, padx=20, pady=18, sticky="w")
        self.top_target_label = ctk.CTkLabel(self.topbar, text="No active target", text_color="#94a3b8")
        self.top_target_label.grid(row=0, column=1, padx=10, sticky="e")
        self.status_badge = ctk.CTkLabel(self.topbar, textvariable=self.status_text, width=90, height=30, corner_radius=15, fg_color="#0f3d2e", text_color="#6ee7b7", font=ctk.CTkFont(size=11, weight="bold"))
        self.status_badge.grid(row=0, column=2, padx=(8, 20))

        self.page_host = ctk.CTkFrame(self.content, corner_radius=0, fg_color="#08131f")
        self.page_host.grid(row=1, column=0, sticky="nsew")
        self.page_host.grid_columnconfigure(0, weight=1)
        self.page_host.grid_rowconfigure(0, weight=1)

        self._build_dashboard()
        self._build_workspaces_page()
        self._build_target_page()
        self._build_modules_page()
        self._build_results_page()
        self._build_graph_page()
        self._build_delta_page()
        self._build_history_page()
        self._build_tools_page()
        self._build_settings_page()

    def _new_page(self, name):
        f = ctk.CTkFrame(self.page_host, fg_color="#08131f", corner_radius=0)
        f.grid(row=0, column=0, sticky="nsew")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(0, weight=1)
        self.pages[name] = f
        return f

    def _show_page(self, name):
        self.pages[name].tkraise()
        for n, b in self.nav_buttons.items():
            b.configure(fg_color="#12304a" if n == name else "transparent", text_color="#67e8f9" if n == name else "#cbd5e1")

    def _card(self, parent, title, key, col):
        card = ctk.CTkFrame(parent, fg_color="#0d1d2d", border_width=1, border_color="#183249", corner_radius=12)
        card.grid(row=0, column=col, padx=6, pady=6, sticky="nsew")
        val = ctk.CTkLabel(card, text="0", font=ctk.CTkFont(size=30, weight="bold"), text_color="#f8fafc")
        val.pack(anchor="w", padx=18, pady=(15, 0))
        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=11), text_color="#7f96aa").pack(anchor="w", padx=18, pady=(0, 15))
        self.metric_labels[key] = val

    def _build_dashboard(self):
        page = self._new_page("Dashboard")
        wrap = ctk.CTkScrollableFrame(page, fg_color="#08131f")
        wrap.grid(row=0, column=0, sticky="nsew", padx=20, pady=16)
        wrap.grid_columnconfigure(0, weight=1)

        hero = ctk.CTkFrame(wrap, fg_color="#0b1a29", border_width=1, border_color="#17334b", corner_radius=14)
        hero.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        hero.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(hero, text="Authorized Target", text_color="#7f96aa", font=ctk.CTkFont(size=11)).grid(row=0, column=0, padx=(18, 6), pady=(16, 2), sticky="w")
        self.target_entry = ctk.CTkEntry(hero, height=42, placeholder_text="example.com", fg_color="#07131f", border_color="#21435f")
        self.target_entry.grid(row=1, column=0, columnspan=2, padx=(18, 8), pady=(0, 16), sticky="ew")
        self.start_btn = ctk.CTkButton(hero, text="START SCAN", width=140, height=42, fg_color="#0891b2", hover_color="#0e7490", font=ctk.CTkFont(weight="bold"), command=self.start_scan)
        self.start_btn.grid(row=1, column=2, padx=(0, 8), pady=(0, 16))
        self.stop_btn = ctk.CTkButton(hero, text="STOP", width=90, height=42, fg_color="#7f1d1d", hover_color="#991b1b", state="disabled", command=self.stop_scan)
        self.stop_btn.grid(row=1, column=3, padx=(0, 18), pady=(0, 16))
        ctk.CTkLabel(hero, text="Profile", text_color="#7f96aa", font=ctk.CTkFont(size=11)).grid(row=0, column=2, padx=8, pady=(16, 2))
        self.profile_menu = ctk.CTkOptionMenu(hero, values=list(PROFILES.keys()), variable=self.current_profile, command=self.apply_profile, width=150, fg_color="#12304a", button_color="#16425f")
        self.profile_menu.grid(row=0, column=3, padx=(0, 18), pady=(10, 2), sticky="e")

        metrics = ctk.CTkFrame(wrap, fg_color="transparent")
        metrics.grid(row=1, column=0, sticky="ew", pady=4)
        for c in range(6): metrics.grid_columnconfigure(c, weight=1)
        for idx, (title, key) in enumerate([("Subdomains", "subdomains"), ("Live Hosts", "live_hosts"), ("Ports", "ports"), ("APIs", "apis"), ("URLs", "urls"), ("Evidence", "total")]):
            self._card(metrics, title, key, idx)

        prog = ctk.CTkFrame(wrap, fg_color="#0b1a29", border_width=1, border_color="#17334b", corner_radius=14)
        prog.grid(row=2, column=0, sticky="ew", pady=10)
        prog.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(prog, text="Scan Pipeline", font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0, padx=18, pady=(14, 0), sticky="w")
        self.pipeline_label = ctk.CTkLabel(prog, textvariable=self.current_module, text_color="#67e8f9")
        self.pipeline_label.grid(row=0, column=1, padx=18, pady=(14, 0), sticky="e")
        self.progress = ctk.CTkProgressBar(prog, height=12, progress_color="#06b6d4")
        self.progress.set(0)
        self.progress.grid(row=1, column=0, columnspan=2, padx=18, pady=14, sticky="ew")

        live = ctk.CTkFrame(wrap, fg_color="#0b1a29", border_width=1, border_color="#17334b", corner_radius=14)
        live.grid(row=3, column=0, sticky="nsew", pady=(0, 10))
        live.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(live, text="Live Activity", font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0, padx=18, pady=(14, 8), sticky="w")
        self.logbox = ctk.CTkTextbox(live, height=300, fg_color="#06101a", text_color="#b8cad8", font=("Consolas", 12), corner_radius=8)
        self.logbox.grid(row=1, column=0, padx=14, pady=(0, 14), sticky="nsew")

    def _build_workspaces_page(self):
        page = self._new_page("Workspaces")
        page.grid_rowconfigure(1, weight=1); page.grid_columnconfigure(0, weight=1)
        top = ctk.CTkFrame(page, fg_color="#08131f")
        top.grid(row=0, column=0, sticky="ew", padx=22, pady=(20,8)); top.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(top, text="Target Workspaces", font=ctk.CTkFont(size=24, weight="bold")).grid(row=0,column=0,columnspan=4,sticky="w")
        self.ws_name = ctk.CTkEntry(top, placeholder_text="Workspace name", width=220); self.ws_name.grid(row=1,column=0,padx=(0,8),pady=10)
        self.ws_notes = ctk.CTkEntry(top, placeholder_text="Notes (optional)"); self.ws_notes.grid(row=1,column=1,padx=8,pady=10,sticky="ew")
        ctk.CTkButton(top,text="Save Current Target",command=self.save_workspace).grid(row=1,column=2,padx=8)
        ctk.CTkButton(top,text="Delete Selected",fg_color="#7f1d1d",hover_color="#991b1b",command=self.delete_workspace).grid(row=1,column=3,padx=(8,0))
        panel=ctk.CTkFrame(page,fg_color="#0b1a29",border_width=1,border_color="#17334b")
        panel.grid(row=1,column=0,sticky="nsew",padx=22,pady=(0,20)); panel.grid_rowconfigure(0,weight=1); panel.grid_columnconfigure(0,weight=1)
        self.ws_tree=ttk.Treeview(panel,columns=("id","name","target","scope","notes"),show="headings")
        for col,w in [("id",55),("name",180),("target",240),("scope",240),("notes",420)]: self.ws_tree.heading(col,text=col.title()); self.ws_tree.column(col,width=w,anchor="w")
        self.ws_tree.grid(row=0,column=0,sticky="nsew",padx=12,pady=12); self.ws_tree.bind("<Double-1>",self.load_workspace)

    def _build_graph_page(self):
        page=self._new_page("Recon Graph"); page.grid_rowconfigure(1,weight=1); page.grid_columnconfigure(0,weight=1)
        head=ctk.CTkFrame(page,fg_color="#08131f"); head.grid(row=0,column=0,sticky="ew",padx=22,pady=(18,8)); head.grid_columnconfigure(0,weight=1)
        ctk.CTkLabel(head,text="Recon Graph",font=ctk.CTkFont(size=24,weight="bold")).grid(row=0,column=0,sticky="w")
        ctk.CTkLabel(head,text="Domain → assets → services → endpoints",text_color="#8ba0b3").grid(row=1,column=0,sticky="w")
        ctk.CTkButton(head,text="Refresh Graph",width=120,command=self.render_graph).grid(row=0,column=1,rowspan=2,padx=8)
        self.graph_canvas=tk.Canvas(page,bg="#06101a",highlightthickness=0)
        self.graph_canvas.grid(row=1,column=0,sticky="nsew",padx=22,pady=(0,20))

    def _build_delta_page(self):
        page=self._new_page("Delta Scan"); page.grid_rowconfigure(1,weight=1); page.grid_columnconfigure(0,weight=1)
        head=ctk.CTkFrame(page,fg_color="#08131f"); head.grid(row=0,column=0,sticky="ew",padx=22,pady=(18,8)); head.grid_columnconfigure(0,weight=1)
        ctk.CTkLabel(head,text="Delta Scan",font=ctk.CTkFont(size=24,weight="bold")).grid(row=0,column=0,sticky="w")
        ctk.CTkLabel(head,text="Compare the current evidence with the previous completed scan for the same target.",text_color="#8ba0b3").grid(row=1,column=0,sticky="w")
        ctk.CTkButton(head,text="Refresh Delta",width=120,command=self.refresh_delta).grid(row=0,column=1,rowspan=2,padx=8)
        self.delta_box=ctk.CTkTextbox(page,fg_color="#06101a",font=("Consolas",12))
        self.delta_box.grid(row=1,column=0,sticky="nsew",padx=22,pady=(0,20))

    def _build_target_page(self):
        page = self._new_page("Target & Scope")
        wrap = ctk.CTkFrame(page, fg_color="#08131f")
        wrap.grid(row=0, column=0, sticky="nsew", padx=24, pady=22)
        wrap.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(wrap, text="Target & Scope", font=ctk.CTkFont(size=24, weight="bold")).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(wrap, text="Define the authorized root domain. WebScopeX will keep HTTP crawling and endpoint requests inside this scope.", text_color="#8ba0b3").grid(row=1, column=0, sticky="w", pady=(4, 18))
        panel = ctk.CTkFrame(wrap, fg_color="#0b1a29", border_width=1, border_color="#17334b")
        panel.grid(row=2, column=0, sticky="ew")
        panel.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(panel, text="Target").grid(row=0, column=0, padx=18, pady=14, sticky="w")
        self.target_entry2 = ctk.CTkEntry(panel, placeholder_text="example.com")
        self.target_entry2.grid(row=0, column=1, padx=18, pady=14, sticky="ew")
        ctk.CTkLabel(panel, text="Scope root").grid(row=1, column=0, padx=18, pady=14, sticky="w")
        self.scope_entry = ctk.CTkEntry(panel, placeholder_text="example.com")
        self.scope_entry.grid(row=1, column=1, padx=18, pady=14, sticky="ew")
        ctk.CTkLabel(panel, text="Output folder").grid(row=2, column=0, padx=18, pady=14, sticky="w")
        self.output_entry = ctk.CTkEntry(panel)
        self.output_entry.insert(0, str(DEFAULT_REPORT_ROOT))
        self.output_entry.grid(row=2, column=1, padx=18, pady=14, sticky="ew")
        ctk.CTkButton(panel, text="Browse", width=90, command=self.browse_output).grid(row=2, column=2, padx=(0, 18), pady=14)
        ctk.CTkButton(panel, text="Copy target to dashboard", command=self.sync_target).grid(row=3, column=1, padx=18, pady=(4, 18), sticky="w")

    def _build_modules_page(self):
        page = self._new_page("Modules")
        wrap = ctk.CTkScrollableFrame(page, fg_color="#08131f")
        wrap.grid(row=0, column=0, sticky="nsew", padx=24, pady=20)
        wrap.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkLabel(wrap, text="Enumeration Modules", font=ctk.CTkFont(size=24, weight="bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 4))
        ctk.CTkLabel(wrap, text="Choose exactly what runs. Profiles can preselect a safe workflow, and Custom lets you tune it.", text_color="#8ba0b3").grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 16))
        for i, (key, name, desc) in enumerate(MODULES):
            card = ctk.CTkFrame(wrap, fg_color="#0b1a29", border_width=1, border_color="#17334b", corner_radius=12)
            card.grid(row=2 + i // 2, column=i % 2, padx=6, pady=6, sticky="ew")
            card.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(card, text=name, font=ctk.CTkFont(size=14, weight="bold")).grid(row=0, column=0, padx=16, pady=(12, 2), sticky="w")
            ctk.CTkLabel(card, text=desc, text_color="#7f96aa", font=ctk.CTkFont(size=11)).grid(row=1, column=0, padx=16, pady=(0, 12), sticky="w")
            var = ctk.BooleanVar(value=True)
            self.module_vars[key] = var
            ctk.CTkSwitch(card, text="", variable=var, command=self._customized).grid(row=0, column=1, rowspan=2, padx=16)

    def _build_results_page(self):
        page = self._new_page("Findings")
        page.grid_rowconfigure(0, weight=1)
        page.grid_columnconfigure(0, weight=1)
        panel = ctk.CTkFrame(page, fg_color="#0b1a29", border_width=1, border_color="#17334b")
        panel.grid(row=0, column=0, sticky="nsew", padx=22, pady=20)
        panel.grid_rowconfigure(2, weight=1)
        panel.grid_columnconfigure(0, weight=1)
        header = ctk.CTkFrame(panel, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=14, pady=(12,6))
        ctk.CTkLabel(header, text="Findings & Evidence", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        ctk.CTkButton(header, text="Export CSV", width=100, command=self.export_findings_csv).pack(side="right")
        ctk.CTkButton(header, text="Open Last Report", width=130, command=self.open_report).pack(side="right", padx=8)
        ctk.CTkButton(header, text="Report Folder", width=115, command=self.open_report_folder).pack(side="right")

        filters = ctk.CTkFrame(panel, fg_color="#08131f", corner_radius=10)
        filters.grid(row=1, column=0, sticky="ew", padx=14, pady=(0,10))
        filters.grid_columnconfigure(0, weight=1)
        self.finding_search = ctk.CTkEntry(filters, placeholder_text="Search module, host, URL, port, evidence...")
        self.finding_search.grid(row=0, column=0, padx=(10,6), pady=10, sticky="ew")
        self.finding_search.bind("<KeyRelease>", lambda _e: self.filter_findings())
        self.finding_module = ctk.StringVar(value="All modules")
        self.finding_module_menu = ctk.CTkOptionMenu(filters, values=["All modules"], variable=self.finding_module, command=lambda _v: self.filter_findings(), width=180)
        self.finding_module_menu.grid(row=0, column=1, padx=6, pady=10)
        self.finding_severity = ctk.StringVar(value="All severities")
        ctk.CTkOptionMenu(filters, values=["All severities","info","low","medium","high"], variable=self.finding_severity, command=lambda _v: self.filter_findings(), width=150).grid(row=0,column=2,padx=6,pady=10)
        ctk.CTkButton(filters, text="Clear", width=78, fg_color="#334155", hover_color="#475569", command=self.clear_findings_filters).grid(row=0,column=3,padx=(6,10),pady=10)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#07131f", fieldbackground="#07131f", foreground="#d7e4ee", rowheight=28, borderwidth=0)
        style.configure("Treeview.Heading", background="#10263a", foreground="#67e8f9", relief="flat", font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", "#123a55")])
        self.tree = ttk.Treeview(panel, columns=("time", "module", "severity", "item", "details"), show="headings")
        for col, width in [("time", 76), ("module", 145), ("severity", 90), ("item", 280), ("details", 650)]:
            self.tree.heading(col, text=col.title())
            self.tree.column(col, width=width, anchor="w")
        self.tree.grid(row=2, column=0, sticky="nsew", padx=14, pady=(0, 14))

    def _build_history_page(self):
        page = self._new_page("History")
        page.grid_rowconfigure(0, weight=1)
        page.grid_columnconfigure(0, weight=1)
        panel = ctk.CTkFrame(page, fg_color="#0b1a29", border_width=1, border_color="#17334b")
        panel.grid(row=0, column=0, sticky="nsew", padx=22, pady=20)
        panel.grid_rowconfigure(1, weight=1)
        panel.grid_columnconfigure(0, weight=1)
        h = ctk.CTkFrame(panel, fg_color="transparent")
        h.grid(row=0, column=0, sticky="ew", padx=14, pady=12)
        ctk.CTkLabel(h, text="Scan History", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        ctk.CTkButton(h, text="Refresh", width=90, command=self.refresh_history).pack(side="right")
        self.history_tree = ttk.Treeview(panel, columns=("id", "target", "profile", "status", "started", "count"), show="headings")
        for col, width in [("id", 55), ("target", 260), ("profile", 90), ("status", 110), ("started", 200), ("count", 90)]:
            self.history_tree.heading(col, text=col.title())
            self.history_tree.column(col, width=width, anchor="w")
        self.history_tree.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))
        self.history_tree.bind("<Double-1>", self.open_history_report)

    def _build_tools_page(self):
        page = self._new_page("Tool Status")
        wrap = ctk.CTkScrollableFrame(page, fg_color="#08131f")
        wrap.grid(row=0, column=0, sticky="nsew", padx=22, pady=20)
        wrap.grid_columnconfigure(0, weight=1)
        header = ctk.CTkFrame(wrap, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(header, text="Tool Installer & Status Manager", font=ctk.CTkFont(size=24, weight="bold")).pack(side="left")
        ctk.CTkButton(header, text="Refresh", width=90, command=self.refresh_tool_status).pack(side="right")
        ctk.CTkButton(header, text="Install Supported", width=145, fg_color="#0e7490", command=self.install_supported_tools).pack(side="right", padx=8)
        ctk.CTkLabel(wrap, text="Built-in modules work without external tools. Install buttons use fixed official package recipes; some tools may require an app restart before PATH refreshes.", text_color="#8ba0b3", wraplength=1050, justify="left").grid(row=1, column=0, sticky="w", pady=(4, 12))
        self.tools_container = ctk.CTkFrame(wrap, fg_color="transparent")
        self.tools_container.grid(row=2, column=0, sticky="ew")
        self.tools_container.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkLabel(wrap, text="Installer Log", font=ctk.CTkFont(size=15, weight="bold")).grid(row=3,column=0,sticky="w",pady=(16,6))
        self.tool_log = ctk.CTkTextbox(wrap, height=170, fg_color="#06101a", text_color="#b8cad8", font=("Consolas", 11))
        self.tool_log.grid(row=4,column=0,sticky="ew")

    def _build_settings_page(self):
        page = self._new_page("Settings")
        wrap = ctk.CTkFrame(page, fg_color="#08131f")
        wrap.grid(row=0, column=0, sticky="nsew", padx=24, pady=22)
        wrap.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(wrap, text="Settings", font=ctk.CTkFont(size=24, weight="bold")).grid(row=0, column=0, sticky="w")
        card = ctk.CTkFrame(wrap, fg_color="#0b1a29", border_width=1, border_color="#17334b")
        card.grid(row=1, column=0, sticky="ew", pady=18)
        card.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(card, text="Request delay (seconds)").grid(row=0, column=0, padx=18, pady=18, sticky="w")
        self.delay_entry = ctk.CTkEntry(card, width=140)
        self.delay_entry.insert(0, "0.05")
        self.delay_entry.grid(row=0, column=1, padx=18, pady=18, sticky="w")
        ctk.CTkLabel(card, text="Small delay reduces accidental load on authorized targets.", text_color="#7f96aa").grid(row=1, column=0, columnspan=2, padx=18, pady=(0, 18), sticky="w")
        self.theme_switch = ctk.CTkSwitch(card, text="Dark mode", command=self.toggle_theme)
        self.theme_switch.select()
        self.theme_switch.grid(row=2, column=0, padx=18, pady=(0, 18), sticky="w")

    def save_workspace(self):
        name=self.ws_name.get().strip() if hasattr(self,"ws_name") else ""
        target=(self.target_entry.get().strip() or self.target_entry2.get().strip())
        if not name or not target:
            messagebox.showwarning("Workspace","Enter a workspace name and target first."); return
        try:
            target=Scanner.normalize_domain(target); scope=Scanner.normalize_domain(self.scope_entry.get().strip() or target)
            self.db.save_workspace(name,target,scope,self.ws_notes.get().strip())
            self.refresh_workspaces()
        except Exception as e: messagebox.showerror("Workspace",str(e))

    def refresh_workspaces(self):
        if not hasattr(self,"ws_tree"): return
        for x in self.ws_tree.get_children(): self.ws_tree.delete(x)
        for r in self.db.list_workspaces(): self.ws_tree.insert("","end",values=(r["id"],r["name"],r["target"],r["scope_root"],r.get("notes", "")))

    def load_workspace(self,_event=None):
        sel=self.ws_tree.selection()
        if not sel: return
        vals=self.ws_tree.item(sel[0],"values"); target,scope=vals[2],vals[3]
        for e in (self.target_entry,self.target_entry2): e.delete(0,"end"); e.insert(0,target)
        self.scope_entry.delete(0,"end"); self.scope_entry.insert(0,scope)
        self.top_target_label.configure(text=f"Workspace target: {target}")
        self._show_page("Dashboard")

    def delete_workspace(self):
        sel=self.ws_tree.selection()
        if not sel: return
        wid=int(self.ws_tree.item(sel[0],"values")[0]); self.db.delete_workspace(wid); self.refresh_workspaces()

    def _graph_from_findings(self):
        root=(self.target_entry.get().strip() or self.target_entry2.get().strip() or "target")
        try: root=Scanner.normalize_domain(root)
        except Exception: pass
        nodes={root:("domain",root)}
        edges=[]
        hosts={root}
        def add_node(nid, kind, label=None):
            if nid not in nodes:
                nodes[nid]=(kind,label or nid)
        def add_edge(a,b,relation):
            if (a,b,relation) not in edges:
                edges.append((a,b,relation))
        for f in self.current_findings:
            if f.module=="Subdomains":
                host=f.details.strip()
                if host:
                    hosts.add(host); add_node(host,"subdomain",host); add_edge(root,host,"subdomain")
            elif f.module=="Live Hosts":
                host=f.item.strip()
                if host:
                    hosts.add(host); add_node(host,"host" if host==root else "subdomain",host); add_edge(root,host,"live")
            elif f.module=="Asset IP":
                host=f.item.strip(); ip=f.details.strip()
                if host and ip:
                    hosts.add(host); add_node(host,"host" if host==root else "subdomain",host)
                    iid=f"ip:{ip}"; add_node(iid,"ip",ip); add_edge(host,iid,"resolves")
            elif f.module=="Ports":
                m=re.match(r"(.+):(\d+)$",str(f.item).strip())
                if m:
                    host,port=m.group(1),m.group(2); hosts.add(host); add_node(host,"host" if host==root else "subdomain",host)
                    pid=f"port:{host}:{port}"; add_node(pid,"port",f"{port}/tcp"); add_edge(host,pid,"port")
                    sm=re.search(r"service=([^|]+)",str(f.details))
                    if sm:
                        svc=sm.group(1).strip(); sid=f"service:{host}:{port}:{svc}"; add_node(sid,"service",svc); add_edge(pid,sid,"service")
            elif f.module in ("API","URLs","Content Discovery","Authentication","JavaScript"):
                vals=[str(f.item),str(f.details)]
                url=next((v for v in vals if v.startswith("http://") or v.startswith("https://")),"")
                if url:
                    host=urlparse(url).hostname or root; add_node(host,"host" if host==root else "subdomain",host)
                    uid=f"endpoint:{url}"; add_node(uid,"endpoint",url); add_edge(host,uid,"endpoint")
        return root,nodes,edges

    def render_graph(self):
        if not hasattr(self,"graph_canvas"): return
        c=self.graph_canvas; c.delete("all"); c.update_idletasks(); w=max(1000,c.winfo_width()); h=max(650,c.winfo_height())
        root,nodes,edges=self._graph_from_findings()
        if len(nodes)<=1:
            c.create_text(w/2,h/2,text="Run a scan to build the Recon Graph",fill="#94a3b8",font=("Segoe UI",18)); return
        order=["domain","subdomain","host","ip","port","service","endpoint"]
        columns={k:[] for k in order}
        for nid,(kind,label) in nodes.items():
            k=kind if kind in columns else "endpoint"
            columns[k].append((nid,label))
        if columns["host"] and root in [x[0] for x in columns["domain"]]:
            pass
        active=[k for k in order if columns[k]]
        xgap=w/(len(active)+1)
        positions={}
        for ci,kind in enumerate(active,1):
            arr=columns[kind][:45]
            ygap=h/(len(arr)+1)
            x=ci*xgap
            for ri,(nid,label) in enumerate(arr,1):
                positions[nid]=(x,ri*ygap)
        for a,b,rel in edges:
            if a in positions and b in positions:
                x1,y1=positions[a]; x2,y2=positions[b]
                c.create_line(x1+38,y1,x2-38,y2,fill="#27465d",width=1,arrow="last")
        palette={"domain":"#22d3ee","subdomain":"#38bdf8","host":"#34d399","ip":"#2dd4bf","port":"#fbbf24","service":"#fb923c","endpoint":"#c084fc"}
        for kind in active:
            title_x=active.index(kind)+1
            c.create_text(title_x*xgap,20,text=kind.upper(),fill="#64748b",font=("Segoe UI",9,"bold"))
        for nid,(kind,label) in nodes.items():
            if nid not in positions: continue
            x,y=positions[nid]; color=palette.get(kind,"#94a3b8")
            short=label if len(label)<=30 else label[:27]+"..."
            c.create_rectangle(x-54,y-19,x+54,y+19,fill="#0b1a29",outline=color,width=2)
            c.create_text(x,y,text=short,fill="#dbeafe",font=("Segoe UI",8),width=102)

    def refresh_delta(self):
        if not hasattr(self, "delta_box"):
            return
        self.delta_box.delete("1.0", "end")
        target = self.target_entry.get().strip() or self.target_entry2.get().strip()
        if not target:
            self.delta_box.insert("end", "Set a target and run a scan first.\n")
            return
        try:
            target = Scanner.normalize_domain(target)
        except Exception:
            return
        prev = self.db.previous_completed(target, exclude_id=self.scan_id)
        if not prev or not prev.get("report_json"):
            self.delta_box.insert("end", "No previous completed scan is available for this target yet.\n")
            return
        d = Scanner.compare_reports(prev.get("report_json"), self.current_findings)
        self.delta_box.insert("end", f"Previous scan: #{prev['id']}  {prev['started_at']}\n")
        self.delta_box.insert("end", f"Added: {len(d['added'])}   Removed: {len(d['removed'])}   Unchanged: {d['unchanged']}\n\n")
        if d.get("by_module"):
            self.delta_box.insert("end", "CHANGE SUMMARY BY MODULE\n" + "-" * 72 + "\n")
            for module,counts in sorted(d["by_module"].items()):
                self.delta_box.insert("end", f"{module:24} +{counts.get('added',0):<4} -{counts.get('removed',0):<4}\n")
            self.delta_box.insert("end", "\n")
        self.delta_box.insert("end", "+ ADDED\n" + "-" * 72 + "\n")
        for m, i, det, sev in d["added"][:300]:
            self.delta_box.insert("end", f"+ [{m}/{sev}] {i} :: {det[:220]}\n")
        self.delta_box.insert("end", "\n- REMOVED\n" + "-" * 72 + "\n")
        for m, i, det, sev in d["removed"][:300]:
            self.delta_box.insert("end", f"- [{m}/{sev}] {i} :: {det[:220]}\n")

    def apply_profile(self, profile):
        selected = PROFILES.get(profile, set())
        if profile != "Custom":
            for key, var in self.module_vars.items():
                var.set(key in selected)

    def _customized(self):
        self.current_profile.set("Custom")

    def browse_output(self):
        p = filedialog.askdirectory()
        if p:
            self.output_entry.delete(0, "end")
            self.output_entry.insert(0, p)

    def sync_target(self):
        t = self.target_entry2.get().strip()
        if t:
            self.target_entry.delete(0, "end")
            self.target_entry.insert(0, t)
        if not self.scope_entry.get().strip() and t:
            self.scope_entry.insert(0, t)
        self._show_page("Dashboard")

    def toggle_theme(self):
        ctk.set_appearance_mode("dark" if self.theme_switch.get() else "light")

    def log(self, msg):
        def _do():
            self.logbox.insert("end", f"{datetime.now().strftime('%H:%M:%S')}  {msg}\n")
            self.logbox.see("end")
        self.after(0, _do)

    def progress_cb(self, n):
        self.after(0, lambda: self.progress.set(max(0, min(1, n / 100.0))))

    def status_cb(self, text):
        self.after(0, lambda: self.current_module.set(text))

    def result_cb(self, finding):
        self.current_findings.append(finding)
        def _do():
            modules = ["All modules"] + sorted(set(f.module for f in self.current_findings))
            if hasattr(self, "finding_module_menu"):
                self.finding_module_menu.configure(values=modules)
            if self._finding_matches(finding):
                self.tree.insert("", "end", values=(finding.timestamp, finding.module, finding.severity, finding.item, finding.details.replace("\n", " ")[:1200]))
            counts = Counter(f.module for f in self.current_findings)
            mapping = {
                "subdomains": counts.get("Subdomains", 0), "live_hosts": counts.get("Live Hosts", 0),
                "ports": counts.get("Ports", 0), "apis": counts.get("API", 0), "urls": counts.get("URLs", 0),
                "total": len(self.current_findings),
            }
            for k, v in mapping.items():
                self.metric_labels[k].configure(text=str(v))
        self.after(0, _do)

    def _finding_matches(self, finding):
        q = self.finding_search.get().strip().lower() if hasattr(self, "finding_search") else ""
        mod = self.finding_module.get() if hasattr(self, "finding_module") else "All modules"
        sev = self.finding_severity.get() if hasattr(self, "finding_severity") else "All severities"
        blob = f"{finding.module} {finding.item} {finding.details} {finding.severity}".lower()
        return (not q or q in blob) and (mod == "All modules" or finding.module == mod) and (sev == "All severities" or finding.severity == sev)

    def filter_findings(self):
        if not hasattr(self, "tree"):
            return
        for row in self.tree.get_children():
            self.tree.delete(row)
        for f in self.current_findings:
            if self._finding_matches(f):
                self.tree.insert("", "end", values=(f.timestamp, f.module, f.severity, f.item, f.details.replace("\n", " ")[:1200]))

    def clear_findings_filters(self):
        if hasattr(self, "finding_search"):
            self.finding_search.delete(0, "end")
        if hasattr(self, "finding_module"):
            self.finding_module.set("All modules")
        if hasattr(self, "finding_severity"):
            self.finding_severity.set("All severities")
        self.filter_findings()

    def export_findings_csv(self):
        if not self.current_findings:
            messagebox.showinfo("Export", "There are no findings to export yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")], initialfile="webscopex_findings.csv")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow(["timestamp","module","severity","item","details"])
            for f in self.current_findings:
                w.writerow([f.timestamp,f.module,f.severity,f.item,f.details])
        messagebox.showinfo("Export", f"Saved findings to:\n{path}")

    def _set_running(self, running):
        self.start_btn.configure(state="disabled" if running else "normal")
        self.stop_btn.configure(state="normal" if running else "disabled")
        self.status_text.set("SCANNING" if running else "READY")
        self.status_badge.configure(fg_color="#4a2f0b" if running else "#0f3d2e", text_color="#fbbf24" if running else "#6ee7b7")

    def start_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            return
        target = self.target_entry.get().strip() or self.target_entry2.get().strip()
        if not target:
            messagebox.showwarning("Target required", "Enter an authorized domain or hostname first.")
            return
        try:
            normalized = Scanner.normalize_domain(target)
        except Exception as e:
            messagebox.showerror("Invalid target", str(e))
            return
        scope = self.scope_entry.get().strip() or normalized
        try:
            scope = Scanner.normalize_domain(scope)
        except Exception as e:
            messagebox.showerror("Invalid scope", str(e))
            return
        if not (normalized == scope or normalized.endswith("." + scope)):
            messagebox.showerror("Scope mismatch", "Target must be the scope root or a subdomain of the declared scope root.")
            return
        if not messagebox.askyesno("Authorization confirmation", f"Confirm that you own {scope} or have explicit permission to enumerate this scope."):
            return

        profile = self.current_profile.get()
        modules = {k: bool(v.get()) for k, v in self.module_vars.items()}
        if not any(modules.values()):
            messagebox.showwarning("No modules", "Enable at least one enumeration module.")
            return
        try:
            delay = float(self.delay_entry.get().strip() or "0.05")
            if delay < 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid setting", "Request delay must be zero or a positive number.")
            return

        root = Path(self.output_entry.get().strip() or DEFAULT_REPORT_ROOT)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        outdir = root / re.sub(r"[^A-Za-z0-9_.-]", "_", normalized) / stamp
        self.stop_event.clear()
        self.current_findings.clear()
        for row in self.tree.get_children():
            self.tree.delete(row)
        for label in self.metric_labels.values():
            label.configure(text="0")
        self.progress.set(0)
        self.top_target_label.configure(text=f"Target: {normalized}   •   Scope: *.{scope}")
        self._set_running(True)
        self.scan_id = self.db.start_scan(normalized, profile)
        self.log(f"{APP_NAME} v{VERSION} starting for {normalized} (scope: {scope})")

        def worker():
            try:
                scanner = Scanner(normalized, outdir, self.log, self.progress_cb, self.result_cb, self.status_cb, modules, self.stop_event, scope, delay)
                hp, jp, summary = scanner.run()
                self.last_report, self.last_json = hp, jp
                status = "stopped" if self.stop_event.is_set() else "completed"
                self.db.finish_scan(self.scan_id, status, hp, jp, len(scanner.findings), summary)
                self.after(0, self.refresh_history)
                self.after(0, self.render_graph)
                self.after(0, self.refresh_delta)
                if status == "completed":
                    self.after(0, lambda: messagebox.showinfo("Scan complete", f"Enumeration completed.\n\nReport:\n{hp}"))
                else:
                    self.after(0, lambda: messagebox.showinfo("Scan stopped", f"Scan was stopped. Partial evidence was saved.\n\nReport:\n{hp}"))
            except Exception as e:
                self.log(f"ERROR: {e}")
                if self.scan_id:
                    self.db.finish_scan(self.scan_id, "error")
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.after(0, lambda: self._set_running(False))
        self.scan_thread = threading.Thread(target=worker, daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        self.stop_event.set()
        self.status_text.set("STOPPING")
        self.current_module.set("Stopping after current request…")
        self.log("Stop requested by user")

    def open_report(self):
        if self.last_report and os.path.exists(self.last_report):
            webbrowser.open(Path(self.last_report).as_uri())
        else:
            messagebox.showinfo("No report", "Run an enumeration first, or open a report from Scan History.")

    def open_report_folder(self):
        p = Path(self.last_report).parent if self.last_report else Path(self.output_entry.get().strip() or DEFAULT_REPORT_ROOT)
        p.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(p))
        except AttributeError:
            webbrowser.open(p.as_uri())

    def refresh_history(self):
        if not hasattr(self, "history_tree"):
            return
        for r in self.history_tree.get_children():
            self.history_tree.delete(r)
        for row in self.db.recent(100):
            self.history_tree.insert("", "end", values=(row["id"], row["target"], row["profile"], row["status"], row["started_at"], row["findings_count"]), tags=(str(row["id"]),))

    def open_history_report(self, _event=None):
        sel = self.history_tree.selection()
        if not sel:
            return
        scan_id = int(self.history_tree.item(sel[0], "values")[0])
        row = next((x for x in self.db.recent(200) if x["id"] == scan_id), None)
        if row and row.get("report_html") and os.path.exists(row["report_html"]):
            webbrowser.open(Path(row["report_html"]).as_uri())

    def refresh_tool_status(self):
        if not hasattr(self, "tools_container"):
            return
        for w in self.tools_container.winfo_children():
            w.destroy()
        for i, (name, spec) in enumerate(TOOL_CATALOG.items()):
            path = locate_tool(name)
            card = ctk.CTkFrame(self.tools_container, fg_color="#0b1a29", border_width=1, border_color="#17334b", corner_radius=10)
            card.grid(row=i // 2, column=i % 2, padx=6, pady=6, sticky="ew")
            card.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(card, text=spec["label"], font=ctk.CTkFont(size=14, weight="bold")).grid(row=0, column=0, padx=14, pady=(12, 2), sticky="w")
            ctk.CTkLabel(card, text=spec.get("description",""), text_color="#7f96aa", font=ctk.CTkFont(size=10)).grid(row=1,column=0,padx=14,pady=(0,2),sticky="w")
            ctk.CTkLabel(card, text=path or "Not found", text_color="#6ee7b7" if path else "#fca5a5", font=ctk.CTkFont(size=10), wraplength=420, justify="left").grid(row=2, column=0, padx=14, pady=(0, 12), sticky="w")
            if path:
                ctk.CTkLabel(card, text="READY", width=76, height=26, corner_radius=13, fg_color="#0f3d2e", text_color="#6ee7b7").grid(row=0,column=1,rowspan=3,padx=14)
            elif spec.get("kind") == "manual":
                ctk.CTkLabel(card, text="MANUAL", width=76, height=26, corner_radius=13, fg_color="#3b2630", text_color="#f9a8d4").grid(row=0,column=1,rowspan=3,padx=14)
            else:
                ctk.CTkButton(card, text="Install", width=76, command=lambda n=name: self.install_tool_async(n)).grid(row=0,column=1,rowspan=3,padx=14)

    def _tool_log(self, text):
        def _do():
            if hasattr(self, "tool_log"):
                self.tool_log.insert("end", f"{datetime.now().strftime('%H:%M:%S')}  {text}\n")
                self.tool_log.see("end")
        self.after(0, _do)

    def install_tool_async(self, name):
        def worker():
            try:
                self._tool_log(f"Installing {name}...")
                install_external_tool(name, self._tool_log)
                self._tool_log(f"{name}: install task completed")
            except Exception as e:
                self._tool_log(f"{name}: ERROR - {e}")
            finally:
                self.after(0, self.refresh_tool_status)
        threading.Thread(target=worker, daemon=True).start()

    def install_supported_tools(self):
        names = [n for n,spec in TOOL_CATALOG.items() if spec.get("kind") != "manual" and not locate_tool(n)]
        if not names:
            messagebox.showinfo("Tool Manager", "All automatically supported tools are already detected.")
            return
        if not messagebox.askyesno("Install tools", "Install supported missing tools?\n\n" + ", ".join(names)):
            return
        def worker():
            for name in names:
                try:
                    self._tool_log(f"Installing {name}...")
                    install_external_tool(name, self._tool_log)
                except Exception as e:
                    self._tool_log(f"{name}: ERROR - {e}")
            self.after(0, self.refresh_tool_status)
        threading.Thread(target=worker, daemon=True).start()

def run_cli(args):
    if not args.authorized:
        raise SystemExit("CLI mode requires --authorized to confirm you own the target or have explicit permission.")
    target = Scanner.normalize_domain(args.target)
    scope = Scanner.normalize_domain(args.scope or target)
    if not (target == scope or target.endswith("." + scope)):
        raise SystemExit("Target must be the scope root or a subdomain of the declared scope.")
    profile = args.profile.title()
    selected = set(PROFILES.get(profile, PROFILES["Standard"]))
    if args.modules:
        requested = {x.strip().lower() for x in args.modules.split(",") if x.strip()}
        valid = {k for k,_,_ in MODULES}
        bad = requested - valid
        if bad:
            raise SystemExit("Unknown modules: " + ", ".join(sorted(bad)))
        selected = requested
    modules = {k:(k in selected) for k,_,_ in MODULES}
    outroot = Path(args.output or DEFAULT_REPORT_ROOT)
    outdir = outroot / target / datetime.now().strftime("%Y%m%d_%H%M%S")
    def log(x): print(x)
    scanner = Scanner(target, outdir, log, lambda n: print(f"Progress {n:.0f}%"), lambda f: None, lambda st: print(f"== {st} =="), modules, scope_root=scope, rate_delay=args.delay)
    hp, jp, summary = scanner.run()
    print(json.dumps(summary, indent=2))
    print("HTML:", hp)
    print("JSON:", jp)
    return 0


def print_tool_status():
    for name, spec in TOOL_CATALOG.items():
        print(f"{name:12} {'READY' if locate_tool(name) else 'MISSING':8} {locate_tool(name) or spec.get('description','')}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"{APP_NAME} v{VERSION} - authorized web enumeration")
    parser.add_argument("--cli", action="store_true", help="Run without the GUI")
    parser.add_argument("--authorized", action="store_true", help="Confirm you own the target or have explicit authorization")
    parser.add_argument("--target", help="Domain or hostname")
    parser.add_argument("--scope", help="Scope root; defaults to target")
    parser.add_argument("--profile", default="Standard", choices=list(PROFILES.keys()), help="Scan profile")
    parser.add_argument("--modules", help="Comma-separated module keys; overrides profile")
    parser.add_argument("--output", help="Output root directory")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between HTTP requests")
    parser.add_argument("--list-modules", action="store_true")
    parser.add_argument("--list-tools", action="store_true")
    args = parser.parse_args()
    if args.list_modules:
        for key,label,desc in MODULES:
            print(f"{key:12} {label:24} {desc}")
        raise SystemExit(0)
    if args.list_tools:
        print_tool_status(); raise SystemExit(0)
    if args.cli:
        if not args.target:
            raise SystemExit("--target is required with --cli")
        raise SystemExit(run_cli(args))
    app = WebScopeXApp()
    app.mainloop()

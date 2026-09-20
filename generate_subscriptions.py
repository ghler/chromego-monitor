#!/usr/bin/env python3
"""
Generate subscription files from local configs
Supports: Clash Meta YAML, Hysteria1, Hysteria2, basic Xray
"""

from __future__ import annotations
import base64
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

import yaml
from rich.console import Console

BASE_DIR = Path(__file__).parent
CONFIG_DIR = BASE_DIR / "configs"
SUB_DIR = BASE_DIR / "subscriptions"
SUB_DIR.mkdir(exist_ok=True)

console = Console()

def load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

def load_yaml(path: Path) -> dict | None:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None

# ---------- Converters ----------

def from_clash_yaml(data: dict, name_prefix: str) -> list[dict]:
    proxies = data.get("proxies") or []
    result = []
    for i, p in enumerate(proxies):
        if not isinstance(p, dict) or not p.get("server"):
            continue
        p = dict(p)  # copy
        p["name"] = f"{name_prefix}-{i+1}" if len(proxies) > 1 else name_prefix
        result.append(p)
    return result

def from_hysteria1(data: dict, name: str) -> list[dict]:
    try:
        server_port = data.get("server", "")
        if ":" in server_port:
            server, port = server_port.rsplit(":", 1)
            port = int(port.split(",")[0])  # take first port if hopping
        else:
            return []

        proxy = {
            "name": name,
            "type": "hysteria",
            "server": server,
            "port": port,
            "auth-str": data.get("auth_str") or data.get("auth", ""),
            "up": data.get("up_mbps", 50),
            "down": data.get("down_mbps", 200),
            "protocol": data.get("protocol", "udp"),
            "sni": data.get("server_name") or data.get("sni", ""),
            "skip-cert-verify": data.get("insecure", True),
            "alpn": [data.get("alpn", "h3")] if data.get("alpn") else ["h3"],
        }
        return [proxy]
    except Exception:
        return []

def from_hysteria2(data: dict, name: str) -> list[dict]:
    try:
        server_port = data.get("server", "")
        if ":" in server_port:
            server, port = server_port.rsplit(":", 1)
            port = int(port.split(",")[0])
        else:
            return []

        tls = data.get("tls", {})
        proxy = {
            "name": name,
            "type": "hysteria2",
            "server": server,
            "port": port,
            "password": data.get("auth") or data.get("password", ""),
            "sni": tls.get("sni", ""),
            "skip-cert-verify": tls.get("insecure", True),
            "fast-open": data.get("fastOpen", True),
        }
        return [proxy]
    except Exception:
        return []

def from_xray(data: dict, name: str) -> list[dict]:
    """Basic Xray → Clash Meta (VLESS / VMess)"""
    try:
        outbounds = data.get("outbounds") or []
        if not outbounds:
            return []

        ob = outbounds[0]
        protocol = ob.get("protocol", "").lower()
        if protocol not in ("vless", "vmess"):
            return []

        settings = ob.get("settings", {})
        vnext = (settings.get("vnext") or [{}])[0]
        user = (vnext.get("users") or [{}])[0]
        stream = ob.get("streamSettings", {})

        server = vnext.get("address", "")
        port = vnext.get("port", 443)
        uuid = user.get("id", "")

        proxy: dict[str, Any] = {
            "name": name,
            "type": protocol,
            "server": server,
            "port": port,
            "uuid": uuid,
            "udp": True,
        }

        network = stream.get("network", "tcp")
        proxy["network"] = network

        security = stream.get("security", "none")
        if security in ("tls", "reality"):
            proxy["tls"] = True
            tls_settings = stream.get("tlsSettings") or stream.get("realitySettings") or {}
            proxy["servername"] = tls_settings.get("serverName", "")
            proxy["client-fingerprint"] = tls_settings.get("fingerprint", "chrome")

            if security == "reality":
                proxy["reality-opts"] = {
                    "public-key": tls_settings.get("publicKey", ""),
                    "short-id": tls_settings.get("shortId", ""),
                }
                if user.get("flow"):
                    proxy["flow"] = user.get("flow")

        if network == "ws":
            ws = stream.get("wsSettings", {})
            proxy["ws-opts"] = {
                "path": ws.get("path", "/"),
                "headers": ws.get("headers", {}),
            }

        return [proxy]
    except Exception:
        return []

# ---------- Main logic ----------

def collect_all_proxies() -> list[dict]:
    all_proxies = []
    seen = set()  # for simple dedup by name

    for category_dir in CONFIG_DIR.iterdir():
        if not category_dir.is_dir():
            continue
        category = category_dir.name

        for file in category_dir.glob("*"):
            if not file.is_file():
                continue

            name = file.stem  # e.g. xray-1, hysteria2-3
            proxies = []

            if file.suffix in (".yaml", ".yml"):
                data = load_yaml(file)
                if data:
                    proxies = from_clash_yaml(data, name)

            elif file.suffix == ".json":
                data = load_json(file)
                if not data:
                    continue

                if category == "hysteria":
                    proxies = from_hysteria1(data, name)
                elif category == "hysteria2":
                    proxies = from_hysteria2(data, name)
                elif category == "xray":
                    proxies = from_xray(data, name)
                # TODO: add juicity, mieru, naiveproxy, shadowquic, singbox later

            for p in proxies:
                if p["name"] not in seen:
                    seen.add(p["name"])
                    all_proxies.append(p)

    return all_proxies

def generate_clash_meta(proxies: list[dict]) -> None:
    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "🚀 Node",
                "type": "select",
                "proxies": [p["name"] for p in proxies] + ["DIRECT"],
            },
            {
                "name": "♻️ Auto",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": [p["name"] for p in proxies],
            },
        ],
        "rules": [
            "GEOIP,LAN,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,🚀 Node",
        ],
    }

    out = SUB_DIR / "clash-meta.yaml"
    out.write_text(yaml.dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
    console.print(f"[green]✓ Clash Meta subscription → {out}[/]")

def generate_v2rayn(proxies: list[dict]) -> None:
    """Generate base64 share links (best-effort)"""
    links = []

    for p in proxies:
        try:
            t = p.get("type")
            name = quote(p["name"])

            if t == "hysteria2":
                # hysteria2://password@server:port?sni=...&insecure=1#name
                link = (
                    f"hysteria2://{p.get('password', '')}@{p['server']}:{p['port']}"
                    f"?sni={p.get('sni', '')}&insecure={1 if p.get('skip-cert-verify') else 0}"
                    f"#{name}"
                )
                links.append(link)

            elif t == "hysteria":
                link = (
                    f"hysteria://{p['server']}:{p['port']}"
                    f"?auth={p.get('auth-str', '')}&peer={p.get('sni', '')}"
                    f"&insecure={1 if p.get('skip-cert-verify') else 0}"
                    f"#{name}"
                )
                links.append(link)

            elif t in ("vless", "vmess"):
                # Very basic – enough for many cases
                uuid = p.get("uuid", "")
                link = f"{t}://{uuid}@{p['server']}:{p['port']}?encryption=none&type={p.get('network', 'tcp')}"
                if p.get("tls"):
                    link += "&security=tls"
                    if p.get("servername"):
                        link += f"&sni={p['servername']}"
                link += f"#{name}"
                links.append(link)

            # TODO: better Reality / WS / other protocols

        except Exception:
            continue

    raw = "\n".join(links)
    b64 = base64.b64encode(raw.encode("utf-8")).decode("utf-8")

    (SUB_DIR / "v2rayn-raw.txt").write_text(raw, encoding="utf-8")
    (SUB_DIR / "v2rayn.txt").write_text(b64, encoding="utf-8")

    console.print(f"[green]✓ V2rayN base64 subscription → subscriptions/v2rayn.txt[/]")
    console.print(f"[green]✓ V2rayN raw links          → subscriptions/v2rayn-raw.txt[/]")

def main():
    console.print("[bold]Generating subscriptions...[/]")
    proxies = collect_all_proxies()
    console.print(f"Collected [cyan]{len(proxies)}[/] unique proxies")

    if not proxies:
        console.print("[yellow]No proxies found. Run monitor.py first.[/]")
        return

    generate_clash_meta(proxies)
    generate_v2rayn(proxies)

    console.print("\n[bold green]Done![/]")
    console.print("You can now use:")
    console.print("  • subscriptions/clash-meta.yaml     → Clash Verge / Mihomo")
    console.print("  • subscriptions/v2rayn.txt          → V2rayN (as subscription)")

if __name__ == "__main__":
    main()
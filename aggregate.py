"""Aggregate public Clash-compatible subscriptions into one safe config."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlparse
from urllib.request import url2pathname

import requests
import yaml


GITHUB_RAW_PATTERN = re.compile(
    r"^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build one Clash config from public sources")
    parser.add_argument("--sources", default="sources.txt", help="File with one URL per line")
    parser.add_argument("--output", default="dist/clash.yaml", help="Output YAML path")
    parser.add_argument("--limit", type=int, default=200, help="Maximum proxy count")
    return parser.parse_args()


def read_sources(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def fetch_url(session: requests.Session, url: str) -> bytes:
    if url.startswith("file://"):
        return Path(url2pathname(urlparse(url).path)).read_bytes()
    headers = {"User-Agent": "clash-node-aggregator/1.0"}
    try:
        response = session.get(url, headers=headers, timeout=25)
        response.raise_for_status()
        return response.content
    except requests.RequestException as first_error:
        match = GITHUB_RAW_PATTERN.match(url)
        if not match:
            raise first_error
        owner, repo, branch, path = match.groups()
        api_url = (
            f"https://api.github.com/repos/{owner}/{repo}/contents/"
            f"{quote(path, safe='/')}?ref={quote(branch, safe='')}"
        )
        if token := os.getenv("GITHUB_TOKEN"):
            headers["Authorization"] = f"Bearer {token}"
        headers["Accept"] = "application/vnd.github+json"
        response = session.get(api_url, headers=headers, timeout=25)
        response.raise_for_status()
        payload = response.json()
        if payload.get("encoding") == "base64" and payload.get("content"):
            return base64.b64decode(payload["content"])
        if payload.get("download_url"):
            response = session.get(payload["download_url"], headers=headers, timeout=25)
            response.raise_for_status()
            return response.content
        raise ValueError(f"Unsupported GitHub API response for {url}")


def decode_text(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="ignore").strip()
    compact = re.sub(r"\s+", "", text)
    if "proxies:" in text or text.startswith("{"):
        return text
    try:
        decoded = base64.b64decode(compact + "=" * (-len(compact) % 4)).decode(
            "utf-8", errors="ignore"
        )
    except Exception:
        return text
    return decoded if "://" in decoded else text


def host_is_public(host: str) -> bool:
    if not host or host.lower() == "localhost":
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def parse_vmess(uri: str) -> dict[str, Any] | None:
    try:
        payload = uri[8:]
        data = json.loads(base64.b64decode(payload + "=" * (-len(payload) % 4)))
        server = data.get("add", "")
        if not host_is_public(server):
            return None
        proxy = {
            "name": data.get("ps") or f"vmess-{server}",
            "type": "vmess",
            "server": server,
            "port": int(data.get("port", 443)),
            "uuid": data.get("id", ""),
            "alterId": int(data.get("aid", 0)),
            "cipher": data.get("scy") or "auto",
            "udp": True,
            "tls": str(data.get("tls", "")).lower() in {"tls", "true", "1"},
        }
        if data.get("net"):
            proxy["network"] = data["net"]
        if data.get("host"):
            proxy["ws-opts"] = {"headers": {"Host": data["host"]}}
        return proxy
    except Exception:
        return None


def parse_uri(uri: str) -> dict[str, Any] | None:
    uri = uri.strip()
    if uri.startswith("vmess://"):
        return parse_vmess(uri)
    try:
        parsed = urlparse(uri)
        host = parsed.hostname or ""
        port = parsed.port or 443
        if not host_is_public(host):
            return None
        query = parse_qs(parsed.query)
        if parsed.scheme == "vless":
            return {
                "name": unquote(parsed.fragment) or f"vless-{host}",
                "type": "vless",
                "server": host,
                "port": port,
                "uuid": unquote(parsed.username or ""),
                "udp": True,
                "tls": query.get("security", ["none"])[0] in {"tls", "reality"},
                "network": query.get("type", ["tcp"])[0],
                "servername": query.get("sni", [""])[0],
                "client-fingerprint": query.get("fp", [""])[0],
            }
        if parsed.scheme == "trojan":
            return {
                "name": unquote(parsed.fragment) or f"trojan-{host}",
                "type": "trojan",
                "server": host,
                "port": port,
                "password": unquote(parsed.username or ""),
                "udp": True,
                "sni": query.get("sni", [""])[0],
                "skip-cert-verify": query.get("allowInsecure", ["0"])[0] == "1",
            }
        if parsed.scheme == "ss":
            if parsed.username and parsed.password:
                cipher = unquote(parsed.username)
                password = unquote(parsed.password)
            else:
                userinfo = parsed.netloc.split("@", 1)[0]
                decoded = base64.b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode()
                cipher, password = decoded.split(":", 1)
            return {
                "name": unquote(parsed.fragment) or f"ss-{host}",
                "type": "ss",
                "server": host,
                "port": port,
                "cipher": cipher,
                "password": password,
                "udp": True,
            }
    except Exception:
        return None
    return None


def parse_uri_lines(text: str) -> list[dict[str, Any]]:
    proxies = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("vmess://", "vless://", "trojan://", "ss://")):
            proxy = parse_uri(line)
            if proxy:
                proxies.append(proxy)
    return proxies


def parse_payload(raw: bytes) -> list[dict[str, Any]]:
    text = decode_text(raw)
    try:
        payload = yaml.safe_load(text)
    except yaml.YAMLError:
        payload = None
    if isinstance(payload, dict) and isinstance(payload.get("proxies"), list):
        return [proxy for proxy in payload["proxies"] if isinstance(proxy, dict)]
    return parse_uri_lines(text)


def proxy_key(proxy: dict[str, Any]) -> tuple:
    return (
        proxy.get("type"),
        proxy.get("server"),
        proxy.get("port"),
        proxy.get("uuid") or proxy.get("password") or proxy.get("cipher"),
    )


def sanitize_proxy(proxy: dict[str, Any], source_index: int, node_index: int) -> dict[str, Any] | None:
    cleaned = {key: value for key, value in proxy.items() if value not in (None, "")}
    server = str(cleaned.get("server", "")).strip()
    proxy_type = str(cleaned.get("type", "")).strip()
    if not server or not host_is_public(server) or not proxy_type:
        return None
    try:
        cleaned["port"] = int(cleaned.get("port", 0))
    except (TypeError, ValueError):
        return None
    if not 1 <= cleaned["port"] <= 65535:
        return None
    cleaned["name"] = f"S{source_index:02d}-{node_index:03d}-{proxy_type}-{server}"
    cleaned["udp"] = bool(cleaned.get("udp", True))
    return cleaned


def build_config(proxies: list[dict[str, Any]]) -> dict[str, Any]:
    names = [proxy["name"] for proxy in proxies]
    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "external-controller": "127.0.0.1:9097",
        "dns": {
            "enable": True,
            "listen": "127.0.0.1:1053",
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "nameserver": ["1.1.1.1", "8.8.8.8"],
            "fallback": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
        },
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "PROXY",
                "type": "select",
                "proxies": ["AUTO", "FALLBACK", *names],
            },
            {
                "name": "AUTO",
                "type": "url-test",
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": names,
            },
            {
                "name": "FALLBACK",
                "type": "fallback",
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": names,
            },
        ],
        "rules": [
            "GEOIP,LAN,DIRECT,no-resolve",
            "GEOIP,CN,DIRECT",
            "MATCH,PROXY",
        ],
    }


def main() -> None:
    args = parse_args()
    sources = read_sources(Path(args.sources))
    session = requests.Session()
    seen: set[tuple] = set()
    proxies: list[dict[str, Any]] = []

    for source_index, source in enumerate(sources, start=1):
        try:
            payload = parse_payload(fetch_url(session, source))
        except Exception as exc:
            print(f"[WARN] source failed: {source} :: {exc}")
            continue
        for node_index, raw_proxy in enumerate(payload, start=1):
            proxy = sanitize_proxy(raw_proxy, source_index, node_index)
            if not proxy:
                continue
            key = proxy_key(proxy)
            if key in seen:
                continue
            seen.add(key)
            proxies.append(proxy)
            if len(proxies) >= args.limit:
                break
        print(f"[INFO] {source}: total={len(proxies)}")
        if len(proxies) >= args.limit:
            break

    if not proxies:
        raise SystemExit("No valid proxies were collected.")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        yaml.safe_dump(
            build_config(proxies),
            allow_unicode=True,
            sort_keys=False,
            width=120,
        ),
        encoding="utf-8",
    )
    print(f"[DONE] wrote {len(proxies)} proxies to {output_path}")


if __name__ == "__main__":
    main()

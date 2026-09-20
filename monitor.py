#!/usr/bin/env python3
"""
ChromeGo Config Monitor – local version
- Shows original remote Last-Modified time
- Shows local file age
- Archives previous version on change
- Detects identical configs
"""

from __future__ import annotations
import hashlib
import json
import os
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

import httpx
import yaml
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

# ---------- Paths ----------
BASE_DIR = Path(__file__).parent
SOURCES_FILE = BASE_DIR / "sources.yaml"
STATE_FILE = BASE_DIR / "state" / "state.json"
CONFIG_DIR = BASE_DIR / "configs"
HISTORY_DIR = BASE_DIR / "history"

console = Console()

def load_sources() -> list[dict]:
    with open(SOURCES_FILE, encoding="utf-8") as f:
        return yaml.safe_load(f)["sources"]

def load_state() -> dict[str, Any]:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {"sources": {}, "content_hashes": {}}

def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def parse_last_modified(header_value: str | None) -> str | None:
    if not header_value:
        return None
    try:
        dt = parsedate_to_datetime(header_value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return None

def human_age(iso_time: str | None) -> str:
    """Convert ISO time to human-readable age (e.g. '3 days ago')"""
    if not iso_time:
        return "—"
    try:
        dt = datetime.fromisoformat(iso_time)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - dt
        seconds = int(delta.total_seconds())
        if seconds < 60:
            return f"{seconds}s ago"
        if seconds < 3600:
            return f"{seconds // 60}m ago"
        if seconds < 86400:
            return f"{seconds // 3600}h ago"
        days = seconds // 86400
        return f"{days}d ago"
    except Exception:
        return "—"

def fetch_with_fallback(urls: list[str]) -> tuple[bytes | None, str | None, str | None]:
    headers = {"User-Agent": "ChromeGo-Monitor/1.3"}
    for url in urls:
        try:
            with httpx.Client(timeout=20, follow_redirects=True) as client:
                r = client.get(url, headers=headers)
                r.raise_for_status()
                last_mod = parse_last_modified(r.headers.get("Last-Modified"))
                return r.content, url, last_mod
        except Exception as e:
            console.print(f"[dim]  mirror failed: {url} → {e}[/]")
    return None, None, None

def archive_previous(src: dict, old_path: Path) -> None:
    if not old_path.exists():
        return
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    hist_dir = HISTORY_DIR / src["id"]
    hist_dir.mkdir(parents=True, exist_ok=True)
    dest = hist_dir / f"{ts}_{old_path.name}"
    old_path.rename(dest)
    console.print(f"[yellow]  Archived previous → {dest.relative_to(BASE_DIR)}[/]")

def check_one(src: dict, state: dict) -> dict:
    result = {
        "id": src["id"],
        "category": src["category"],
        "updated": False,
        "identical_to": [],
        "error": None,
        "remote_last_modified": None,
        "local_mtime": None,
        "url_used": None,
    }

    content, used_url, remote_last_mod = fetch_with_fallback(src["urls"])
    if content is None:
        result["error"] = "All mirrors failed"
        return result

    content_hash = sha256(content)

    # Global deduplication
    for other_id, other_hash in state.get("content_hashes", {}).items():
        if other_id != src["id"] and other_hash == content_hash:
            result["identical_to"].append(other_id)

    src_state = state["sources"].setdefault(src["id"], {})
    old_hash = src_state.get("hash")

    config_path = CONFIG_DIR / src["category"] / src["filename"]
    config_path.parent.mkdir(parents=True, exist_ok=True)

    # Get current local mtime (before possible update)
    if config_path.exists():
        mtime = datetime.fromtimestamp(config_path.stat().st_mtime, tz=timezone.utc)
        result["local_mtime"] = mtime.isoformat()

    if old_hash != content_hash:
        # Content changed → archive + save
        if config_path.exists():
            archive_previous(src, config_path)

        config_path.write_bytes(content)

        # Update local mtime after write
        mtime = datetime.fromtimestamp(config_path.stat().st_mtime, tz=timezone.utc)
        result["local_mtime"] = mtime.isoformat()

        src_state["hash"] = content_hash
        src_state["remote_last_modified"] = remote_last_mod
        src_state["url"] = used_url
        state["content_hashes"][src["id"]] = content_hash

        result["updated"] = True
        result["remote_last_modified"] = remote_last_mod
        result["url_used"] = used_url
    else:
        # No content change
        if remote_last_mod:
            src_state["remote_last_modified"] = remote_last_mod
        result["remote_last_modified"] = src_state.get("remote_last_modified")
        result["url_used"] = src_state.get("url")

    return result

def print_status(results: list[dict]) -> None:
    table = Table(
        title="ChromeGo Config Monitor – Status",
        show_lines=True,
        box=box.ROUNDED
    )
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Category")
    table.add_column("Remote Last-Modified", style="green")
    table.add_column("Local File Age", style="blue")
    table.add_column("Status")
    table.add_column("Identical To", style="magenta")

    updated = unchanged = failed = 0

    for r in results:
        if r["error"]:
            status = f"[red]{r['error']}[/]"
            failed += 1
        elif r["updated"]:
            status = "[green]Updated[/]"
            updated += 1
        else:
            status = "[dim]Unchanged[/]"
            unchanged += 1

        identical = ", ".join(r["identical_to"]) if r["identical_to"] else "—"

        remote = r["remote_last_modified"]
        remote_display = remote[:19].replace("T", " ") if remote else "[dim]unknown[/]"

        local_age = human_age(r["local_mtime"])

        table.add_row(
            r["id"],
            r["category"],
            remote_display,
            local_age,
            status,
            identical
        )

    console.print(table)

    # Summary
    summary = (
        f"[green]Updated: {updated}[/]   "
        f"[dim]Unchanged: {unchanged}[/]   "
        f"[red]Failed: {failed}[/]   "
        f"Total: {len(results)}"
    )
    console.print(Panel(summary, title="Run Summary", style="bold"))

    # Identical groups
    dup_groups = {}
    for r in results:
        if r["identical_to"]:
            key = tuple(sorted([r["id"]] + r["identical_to"]))
            dup_groups[key] = True

    if dup_groups:
        console.print(Panel(
            "\n".join(" ≡ ".join(group) for group in sorted(dup_groups)),
            title="[bold yellow]Currently Identical Configs[/]",
            border_style="yellow"
        ))

def main():
    console.print(Panel.fit(
        "[bold]ChromeGo Config Monitor[/]\n"
        "Remote Last-Modified  •  Local File Age  •  Auto-archive",
        style="blue"
    ))

    sources = load_sources()
    state = load_state()

    results = []
    for src in sources:
        console.print(f"\n→ Checking [cyan]{src['id']}[/] ...")
        res = check_one(src, state)
        results.append(res)

        if res["updated"]:
            console.print(f"[green]  ✓ Content updated[/]")
        elif res["error"]:
            console.print(f"[red]  ✗ {res['error']}[/]")
        else:
            console.print(f"[dim]  = No content change[/]")

    save_state(state)
    console.print()
    print_status(results)
    console.print("\n[bold green]Done.[/] State saved to state/state.json")

if __name__ == "__main__":
    main()
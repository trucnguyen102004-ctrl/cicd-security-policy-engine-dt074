#!/usr/bin/env python3
"""Send a short gate-failure notice to Discord / Slack / Telegram (stdlib only).

Configured through environment variables (unset channels are skipped):
  DISCORD_WEBHOOK_URL, SLACK_WEBHOOK_URL, TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID
Only rule ids, file paths and counts are sent — never code snippets or secret values.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def summary(results: Path, run_url: str) -> str:
    decision = json.loads((results / "decision.json").read_text(encoding="utf-8"))
    findings = json.loads((results / "findings.json").read_text(encoding="utf-8"))
    blocking = [f for f in findings if f["blocking"]]
    repo = os.environ.get("GITHUB_REPOSITORY", "local")
    ref = os.environ.get("GITHUB_HEAD_REF") or os.environ.get("GITHUB_REF_NAME", "")
    lines = [f"🔒 Security gate {decision['decision']} — {repo} ({ref})",
             f"{len(blocking)} blocking finding(s), {decision['counts']['total']} total, "
             f"{decision['total_seconds']:.1f}s"]
    for f in blocking[:5]:
        cwe = (f["cwe"] or ["?"])[0]
        where = f["file"] if f["category"] == "sca" else f"{f['file']}:{f['line']}"
        lines.append(f"• [{f['severity']}] {cwe} {f['rule_id'].rsplit('.', 1)[-1]} @ {where}")
    if len(blocking) > 5:
        lines.append(f"• … and {len(blocking) - 5} more")
    if run_url:
        lines.append(run_url)
    return "\n".join(lines)


def post(url: str, payload: dict | None = None, form: dict | None = None) -> None:
    data = json.dumps(payload).encode() if payload is not None else urllib.parse.urlencode(form).encode()
    # Discord (behind Cloudflare) rejects the default "Python-urllib" agent with 403.
    headers = {"User-Agent": "DT074-SecurityGate/1.0 (+https://github.com/trucnguyen102004-ctrl/cicd-security-policy-engine-dt074)"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except urllib.error.HTTPError as err:   # surface the reason in the CI log
        raise RuntimeError(f"HTTP {err.code}: {err.read()[:200]!r}") from None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, default=Path(".gate-out"))
    ap.add_argument("--run-url", default="")
    ap.add_argument("--dry-run", action="store_true", help="print the message instead of sending")
    args = ap.parse_args()
    text = summary(args.results, args.run_url)
    if args.dry_run:
        print(text)
        return 0
    sent = 0
    channels = [
        ("discord", os.environ.get("DISCORD_WEBHOOK_URL"), lambda u: post(u, {"content": text[:1900]})),
        ("slack", os.environ.get("SLACK_WEBHOOK_URL"), lambda u: post(u, {"text": text})),
    ]
    tg_token, tg_chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if tg_token and tg_chat:
        channels.append(("telegram", f"https://api.telegram.org/bot{tg_token}/sendMessage",
                         lambda u: post(u, form={"chat_id": tg_chat, "text": text})))
    for name, url, send in channels:
        if not url:
            continue
        try:
            send(url)
            sent += 1
            print(f"[notify] sent to {name}")
        except Exception as exc:  # notification must never break the pipeline
            print(f"[notify] {name} failed: {exc}", file=sys.stderr)
    if not sent:
        print("[notify] no channel configured (set DISCORD_WEBHOOK_URL / SLACK_WEBHOOK_URL / TELEGRAM_*)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

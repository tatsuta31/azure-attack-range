"""Splunk custom alert action: post a detection to a Discord webhook.

Splunk runs this as `python3 discord.py --execute` and writes the alert
payload (JSON) to stdin. Anything printed to stderr ends up in splunkd.log
(search: index=_internal sendmodalert action_name=discord).

Standard library only, so nothing has to be pip-installed on the Splunk host.
"""

import json
import sys
import time
import urllib.error
import urllib.request

WEBHOOK_PREFIXES = (
    "https://discord.com/api/webhooks/",
    "https://discordapp.com/api/webhooks/",
)
DEFAULT_FIELDS = "dest, user, src_user, process, command, signature_id"
MAX_FIELDS = 10          # Discord allows 25 per embed; keep the message readable
MAX_VALUE_LEN = 1000     # Discord limit is 1024 per field value
MAX_RETRIES = 3


def log(level, msg):
    print(f"{level} {msg}", file=sys.stderr)


def to_text(value):
    """Splunk gives multivalue fields as lists. Flatten and fence for Discord."""
    if isinstance(value, list):
        value = "\n".join(str(v) for v in value)
    text = str(value).replace("`", "'")  # a stray backtick would break the code block
    if len(text) > MAX_VALUE_LEN - 8:
        text = text[: MAX_VALUE_LEN - 11] + "..."
    return f"```{text}```"


def build_message(payload):
    cfg = payload.get("configuration", {})
    result = payload.get("result", {}) or {}

    wanted = [f.strip() for f in (cfg.get("fields") or DEFAULT_FIELDS).split(",") if f.strip()]
    fields = [
        {"name": name, "value": to_text(result[name]), "inline": False}
        for name in wanted
        if result.get(name) not in (None, "", [])
    ][:MAX_FIELDS]

    embed = {
        "title": payload.get("search_name", "Splunk alert")[:256],
        "color": 0xD32F2F,
        "fields": fields,
        "footer": {"text": f"app={payload.get('app', '?')}  sid={payload.get('sid', '?')}"[:2048]},
    }
    link = payload.get("results_link")
    if link:
        embed["url"] = link
    if not fields:
        embed["description"] = "（指定したフィールドが結果に無かった。fields 設定を確認）"

    return {
        "username": "Splunk",
        "embeds": [embed],
        # Result values come from attacker-controlled logs. Never let them ping @everyone.
        "allowed_mentions": {"parse": []},
    }


def post(url, body):
    data = json.dumps(body).encode("utf-8")
    for attempt in range(1, MAX_RETRIES + 1):
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                # Discord (Cloudflare) rejects the default Python-urllib agent with 403.
                "User-Agent": "SplunkAlertAction/0.1",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                log("INFO", f"Discord accepted the message (HTTP {resp.status})")
                return True
        except urllib.error.HTTPError as e:
            if e.code == 429:  # rate limited: wait as told, then retry
                try:
                    wait = float(json.loads(e.read().decode("utf-8")).get("retry_after", 2))
                except Exception:
                    wait = 2.0
                log("WARN", f"rate limited, retry in {wait:.1f}s (attempt {attempt}/{MAX_RETRIES})")
                time.sleep(min(wait, 30))
                continue
            log("ERROR", f"Discord returned HTTP {e.code}: {e.read()[:300]!r}")
            return False
        except Exception as e:  # network error, timeout, DNS
            log("ERROR", f"request failed: {e} (attempt {attempt}/{MAX_RETRIES})")
            time.sleep(2)
    return False


def main():
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        log("FATAL", "unsupported execution mode (expected --execute)")
        return 1

    payload = json.loads(sys.stdin.read())
    url = (payload.get("configuration", {}).get("webhook_url") or "").strip()
    if not url.startswith(WEBHOOK_PREFIXES):
        log("ERROR", "webhook_url is empty or not a Discord webhook URL. "
                     "Set it in local/alert_actions.conf of aar_discord_alert.")
        return 2

    return 0 if post(url, build_message(payload)) else 3


if __name__ == "__main__":
    sys.exit(main())

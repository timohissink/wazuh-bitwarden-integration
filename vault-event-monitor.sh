#!/usr/bin/env bash
# ==============================================================================
# Bitwarden -> Wazuh integration: install / manage / uninstall
# ==============================================================================
# One self-contained script that guides you through setting up (and later
# managing) a Bitwarden-to-Wazuh event pipeline: a Python poller, one or
# more Bitwarden organizations, a Wazuh <localfile> entry, and 45 detection
# rules.
#
# Interactive use (recommended for first-time setup):
#   sudo bash vault-event-monitor.sh
#     -> shows a menu: Install / Add organization / Remove organization /
#        Status / Run the poller now / Update rules & configuration /
#        Uninstall / Exit
#
# Non-interactive use (for automation/CI/repeated testing):
#   sudo bash vault-event-monitor.sh install [--name NAME --client-id ID --client-secret SECRET]
#   sudo bash vault-event-monitor.sh add-org --name NAME --client-id ID --client-secret SECRET [--identity-url URL] [--api-url URL]
#   sudo bash vault-event-monitor.sh remove-org --name NAME
#   sudo bash vault-event-monitor.sh status
#   sudo bash vault-event-monitor.sh run-now
#   sudo bash vault-event-monitor.sh update
#   sudo bash vault-event-monitor.sh uninstall [--force]
#   sudo bash vault-event-monitor.sh help
#
# Prerequisites:
#   - A working Wazuh manager (this does NOT install Wazuh itself)
#   - Root / sudo access
#   - Outbound HTTPS access to Bitwarden's API (or your self-hosted instance)
#   - At least one Bitwarden organization on a Teams or Enterprise plan,
#     with an organization API key
# ==============================================================================

set -uo pipefail
# Note: deliberately NOT using `set -e` at the top level. This script has
# many recoverable situations (a missing org during removal, a failed
# validation that should roll back rather than crash, etc.) that are
# handled explicitly with their own error checks and messages instead.

# --- Paths --------------------------------------------------------------------
SCRIPT_DIR="/opt/scripts"
POLLER_SCRIPT="${SCRIPT_DIR}/bitwarden_wazuh_poller.py"

CONFIG_DIR="/etc/bitwarden-wazuh"
ORGS_CONFIG="${CONFIG_DIR}/organizations.json"
ORGS_EXAMPLE="${CONFIG_DIR}/organizations.json.example"
README_FILE="${CONFIG_DIR}/README.md"

LOG_DIR="/var/log/bitwarden"
CRON_FILE="/etc/cron.d/bitwarden-wazuh"
# Every minute: close to the practical floor. Bitwarden's own clients
# batch-upload events to Bitwarden's server only every ~60 seconds (see
# bitwarden.com/help/event-logs), so even instant polling on our side
# can't make an event visible sooner than that.
CRON_SCHEDULE="* * * * *"

OSSEC_CONF="/var/ossec/etc/ossec.conf"
LOCAL_RULES="/var/ossec/etc/rules/local_rules.xml"

WAZUH_GROUP="wazuh"   # standard service account group created by every Wazuh install

LOCALFILE_BEGIN="<!-- BEGIN bitwarden-wazuh-localfile -->"
LOCALFILE_END="<!-- END bitwarden-wazuh-localfile -->"
RULES_BEGIN="<!-- BEGIN bitwarden-wazuh-rules -->"
RULES_END="<!-- END bitwarden-wazuh-rules -->"
RULES_ID_PATTERN='id="1002[5-9][0-9]"'   # covers 100250-100299 (our IDs: 100250-100294)

# ------------------------------------------------------------------------------

is_tty() {
  [[ -t 0 ]]
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (or via sudo)." >&2
    exit 1
  fi
}

require_wazuh_manager() {
  if [[ ! -x /var/ossec/bin/wazuh-analysisd ]] || [[ ! -x /var/ossec/bin/wazuh-logcollector ]]; then
    echo "This doesn't look like a Wazuh manager host:" >&2
    echo "  /var/ossec/bin/wazuh-analysisd or wazuh-logcollector not found/executable." >&2
    echo "This script must be run on the Wazuh manager itself." >&2
    exit 1
  fi
  if ! command -v python3 &>/dev/null; then
    echo "python3 is required but was not found on this system." >&2
    exit 1
  fi
}

is_installed() {
  [[ -f "${POLLER_SCRIPT}" ]]
}

require_installed() {
  if ! is_installed; then
    echo "The integration isn't installed yet. Choose \"Install integration\" first." >&2
    return 1
  fi
  return 0
}

# Prompts a yes/no question. Usage: prompt_yes_no "Question?" "y" -> 0 if yes
prompt_yes_no() {
  local question="$1" default="${2:-n}" reply
  local hint="y/N"
  [[ "${default}" == "y" ]] && hint="Y/n"
  read -r -p "${question} [${hint}]: " reply
  reply="${reply:-${default}}"
  [[ "${reply}" =~ ^[Yy]$ ]]
}
# ==============================================================================
# Infrastructure functions
# ==============================================================================

ensure_directories() {
  mkdir -p "${SCRIPT_DIR}" "${CONFIG_DIR}" "${LOG_DIR}"
}

write_poller_script() {
  cat > "${POLLER_SCRIPT}" <<'PYEOF'
#!/usr/bin/env python3
"""
Fetches Bitwarden organization events for one or more organizations via
the Public API, and writes them as JSON lines to a shared log file that
Wazuh monitors via <localfile>. Each event is tagged with which
organization it came from ("organization" field), so Wazuh rules/searches
can filter per organization later if needed.

Enrichment: for each organization independently, actingUserId and
memberId (organization-scoped GUIDs) are resolved to the member's email
address where possible, using that organization's own /public/members
endpoint. The resolved value replaces the field in place (so existing
consumers/rules that reference $(actingUserId) keep working unchanged);
the original GUID is preserved under a "...Raw" field for traceability.
itemId is intentionally never resolved to an item name - Bitwarden
encrypts item names client-side (zero-knowledge architecture), so the
server has no readable name to give us.

Configuration: organizations are defined in a JSON file (default:
/etc/bitwarden-wazuh/organizations.json), for example:

[
  {
    "name": "Acme Corp",
    "client_id": "organization.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  },
  {
    "name": "Acme Self-Hosted",
    "client_id": "organization.yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
    "client_secret": "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
    "identity_url": "https://bitwarden.acme.example.com/identity/connect/token",
    "api_url": "https://bitwarden.acme.example.com/api/public"
  }
]

"identity_url" and "api_url" are optional per organization and default to
Bitwarden Cloud - set them for a self-hosted Bitwarden instance. Add as
many organization objects to the array as you need; each is processed
independently, and a failure in one organization does not stop the others.

Plain JSON has no comment syntax, so an entry with a "_comment" key (and
nothing else required) is treated as documentation and skipped - useful
for leaving a usage hint inside the file itself without it being treated
as a real (and therefore failing) organization, e.g.:

  { "_comment": "Add another organization here, like the one above." }

This file contains secrets (client_secret per organization) - keep it
root-owned with 600 permissions.

Requires: pip install requests
Run this periodically via cron, e.g. every minute.
"""

import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

import requests

DEFAULT_IDENTITY_URL = "https://identity.bitwarden.com/connect/token"
DEFAULT_API_BASE_URL = "https://api.bitwarden.com/public"

ORGS_CONFIG_FILE = os.environ.get("BW_ORGS_CONFIG", "/etc/bitwarden-wazuh/organizations.json")
LOG_FILE = "/var/log/bitwarden/events.log"
STATE_DIR = "/var/log/bitwarden"

# How long to keep using a cached members list before refreshing it from
# the API. Member lists change rarely, so there's no need to fetch it on
# every poll. Applies to every organization.
MEMBERS_CACHE_TTL_MINUTES = int(os.environ.get("BW_MEMBERS_CACHE_TTL_MINUTES", "60"))


def slugify(name: str) -> str:
    """Turns an organization name into a safe filename fragment."""
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", name.strip().lower())
    slug = slug.strip("_")
    return slug or "org"


def load_organizations() -> list:
    """Loads, validates, and normalizes the organizations config file."""
    if not os.path.exists(ORGS_CONFIG_FILE):
        raise SystemExit(
            f"Organizations config file not found: {ORGS_CONFIG_FILE}\n"
            f"Create it with a JSON array of {{name, client_id, client_secret}} objects."
        )

    with open(ORGS_CONFIG_FILE, "r") as f:
        raw = json.load(f)

    if not isinstance(raw, list) or not raw:
        raise SystemExit(
            f"{ORGS_CONFIG_FILE} must contain a non-empty JSON array of organizations."
        )

    orgs = []
    seen_names = set()
    seen_slugs = {}
    for i, entry in enumerate(raw):
        # Entries with a "_comment" key are documentation only (e.g. showing
        # how to add another organization) and are never processed.
        if "_comment" in entry:
            continue

        missing = [k for k in ("name", "client_id", "client_secret") if not entry.get(k)]
        if missing:
            raise SystemExit(
                f"Organization #{i + 1} in {ORGS_CONFIG_FILE} is missing: {', '.join(missing)}"
            )
        if entry["name"] in seen_names:
            raise SystemExit(f"Duplicate organization name in {ORGS_CONFIG_FILE}: {entry['name']}")
        seen_names.add(entry["name"])

        slug = slugify(entry["name"])
        if slug in seen_slugs:
            raise SystemExit(
                f"Organization names '{entry['name']}' and '{seen_slugs[slug]}' produce the "
                f"same internal identifier ('{slug}') - please make them more distinct."
            )
        seen_slugs[slug] = entry["name"]

        api_base = entry.get("api_url", DEFAULT_API_BASE_URL)
        orgs.append(
            {
                "name": entry["name"],
                "client_id": entry["client_id"],
                "client_secret": entry["client_secret"],
                "identity_url": entry.get("identity_url", DEFAULT_IDENTITY_URL),
                "events_url": f"{api_base}/events",
                "members_url": f"{api_base}/members",
                "state_file": os.path.join(STATE_DIR, f".last_run.{slug}"),
                "members_cache_file": os.path.join(STATE_DIR, f".members_cache.{slug}.json"),
            }
        )
    return orgs


def get_access_token(org: dict) -> str:
    resp = requests.post(
        org["identity_url"],
        data={
            "grant_type": "client_credentials",
            "scope": "api.organization",
            "client_id": org["client_id"],
            "client_secret": org["client_secret"],
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def get_last_run(org: dict) -> str:
    if os.path.exists(org["state_file"]):
        with open(org["state_file"], "r") as f:
            return f.read().strip()
    # First run for this organization: look back 24 hours.
    start = datetime.now(timezone.utc) - timedelta(hours=24)
    return start.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def save_last_run(org: dict, ts: str) -> None:
    os.makedirs(os.path.dirname(org["state_file"]), exist_ok=True)
    with open(org["state_file"], "w") as f:
        f.write(ts)


def fetch_events(org: dict, token: str, start: str) -> tuple:
    headers = {"Authorization": f"Bearer {token}"}
    end = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    events = []
    params = {"start": start, "end": end}

    while True:
        resp = requests.get(org["events_url"], headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        events.extend(data.get("data", []))

        token_cont = data.get("continuationToken")
        if not token_cont:
            break
        params = {"start": start, "end": end, "continuationToken": token_cont}

    return events, end


def fetch_members(org: dict, token: str) -> dict:
    """
    Fetches the organization's member list and returns a combined lookup
    dict, keyed by BOTH id types Bitwarden exposes for a member:

      - "id"     the organization-membership UUID (this is what the
                  event field "memberId" refers to)
      - "userId" the member's underlying, global Bitwarden account UUID
                  (this is what the event field "actingUserId" refers to)

    Both keys map to the same email, so a single dict resolves either
    event field without the caller needing to know which is which.
    """
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(org["members_url"], headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    member_map = {}
    for m in data.get("data", []):
        email = m.get("email")
        if not email:
            continue
        if m.get("id"):
            member_map[m["id"]] = email
        if m.get("userId"):
            member_map[m["userId"]] = email
    return member_map


def load_members_cache(org: dict, max_age_minutes=None):
    """
    Returns (members_dict, is_fresh).
    (None, False) if no cache file exists yet for this organization.
    """
    cache_file = org["members_cache_file"]
    if not os.path.exists(cache_file):
        return None, False

    with open(cache_file, "r") as f:
        cache = json.load(f)

    fetched_at = datetime.fromisoformat(cache["fetched_at"].replace("Z", "+00:00"))
    age_minutes = (datetime.now(timezone.utc) - fetched_at).total_seconds() / 60
    is_fresh = max_age_minutes is not None and age_minutes <= max_age_minutes
    return cache["members"], is_fresh


def save_members_cache(org: dict, members: dict) -> None:
    cache_file = org["members_cache_file"]
    os.makedirs(os.path.dirname(cache_file), exist_ok=True)
    cache = {
        "fetched_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        ),
        "members": members,
    }
    with open(cache_file, "w") as f:
        json.dump(cache, f)


def get_member_map(org: dict, token: str) -> dict:
    """
    Returns {id_or_userId: email} for this organization, using a cached
    copy when it's still fresh. Falls back to a stale cache (or an empty
    map, if no cache exists at all) if refreshing from the API fails - a
    members-API hiccup should degrade enrichment gracefully, not break
    event collection for this (or any other) organization.
    """
    cached_members, is_fresh = load_members_cache(org, MEMBERS_CACHE_TTL_MINUTES)
    if is_fresh:
        return cached_members

    try:
        members = fetch_members(org, token)
        save_members_cache(org, members)
        return members
    except Exception as exc:
        if cached_members is not None:
            print(
                f"[{org['name']}] Warning: could not refresh members list ({exc}); "
                f"using stale cache.",
                file=sys.stderr,
            )
            return cached_members
        print(
            f"[{org['name']}] Warning: could not fetch members list ({exc}); "
            f"proceeding without member-email enrichment.",
            file=sys.stderr,
        )
        return {}


def enrich_event(event: dict, member_map: dict) -> dict:
    """
    Replaces actingUserId/memberId with the resolved email address where
    possible, preserving the original GUID under a "...Raw" field. Leaves
    the event untouched if the GUID isn't in the member map (e.g. a former
    member, a Provider actor, or a null field).
    """
    for id_field, raw_field in (("actingUserId", "actingUserIdRaw"), ("memberId", "memberIdRaw")):
        guid = event.get(id_field)
        if guid and guid in member_map:
            event[raw_field] = guid
            event[id_field] = member_map[guid]
    return event


def write_events(events: list) -> None:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    # Always open/create the file, even with 0 events, so the file is
    # guaranteed to exist and Wazuh's <localfile> doesn't choke on it.
    with open(LOG_FILE, "a") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")


def process_organization(org: dict) -> int:
    """Processes a single organization end-to-end. Returns the event count."""
    start = get_last_run(org)
    token = get_access_token(org)
    member_map = get_member_map(org, token)

    events, new_checkpoint = fetch_events(org, token, start)

    enriched = 0
    for event in events:
        event["_source"] = "bitwarden"
        event["organization"] = org["name"]
        enrich_event(event, member_map)
        if "actingUserIdRaw" in event or "memberIdRaw" in event:
            enriched += 1

    write_events(events)
    save_last_run(org, new_checkpoint)

    print(
        f"[{org['name']}] Time window queried: {start} to {new_checkpoint}\n"
        f"[{org['name']}] {len(events)} events fetched and written to {LOG_FILE} "
        f"({enriched} enriched with a member email, {len(member_map)} members known)"
    )
    return len(events)


def main():
    orgs = load_organizations()
    total_events = 0
    failed_orgs = []

    for org in orgs:
        try:
            total_events += process_organization(org)
        except Exception as exc:
            failed_orgs.append(org["name"])
            print(f"[{org['name']}] ERROR: {exc}", file=sys.stderr)

    print(f"Done: {total_events} total events across {len(orgs)} organization(s).")
    if failed_orgs:
        print(f"Organizations that failed this run: {', '.join(failed_orgs)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
PYEOF
  chmod 750 "${POLLER_SCRIPT}"
}

ensure_config_scaffolding() {
  cat > "${ORGS_EXAMPLE}" <<'ORGS_EXAMPLE_EOF'
[
  {
    "name": "Acme Corp",
    "client_id": "organization.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  },
  {
    "name": "Acme Self-Hosted",
    "client_id": "organization.yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
    "client_secret": "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
    "identity_url": "https://bitwarden.acme.example.com/identity/connect/token",
    "api_url": "https://bitwarden.acme.example.com/api/public"
  }
]
ORGS_EXAMPLE_EOF
  chmod 644 "${ORGS_EXAMPLE}"

  if [[ ! -f "${ORGS_CONFIG}" ]]; then
    cat > "${ORGS_CONFIG}" <<'ORGS_EOF'
[
  {
    "_comment": "Add another organization here, like the one below - or use: sudo bash vault-event-monitor.sh add-org"
  }
]
ORGS_EOF
    chmod 600 "${ORGS_CONFIG}"
    chown root:root "${ORGS_CONFIG}"
  fi

  cat > "${README_FILE}" <<'README_EOF'
# Bitwarden -> Wazuh integration

This integration polls Bitwarden's organization Event Logs (via the
Bitwarden Public API) for one or more organizations, resolves actor/member
GUIDs to email addresses where possible, and feeds the result into this
Wazuh manager as JSON alerts.

## Managing organizations

Use the management script rather than editing `organizations.json` by hand
where possible:

```bash
sudo bash vault-event-monitor.sh add-org --name "Acme Corp" --client-id "organization.xxxx" --client-secret "xxxx"
sudo bash vault-event-monitor.sh remove-org --name "Acme Corp"
sudo bash vault-event-monitor.sh status
```

Or run it without arguments for an interactive menu.

### Getting a client_id / client_secret

1. Log in to the Bitwarden web vault as an organization Owner/Admin
   (requires a Teams or Enterprise plan).
2. Open the Admin Console -> **Settings** -> **Organization info** ->
   **API Key**, and view (or rotate) the key.
3. Copy the `client_id` (starts with `organization.`) and the
   `client_secret`.

### Self-hosted Bitwarden

Pass `--identity-url` and `--api-url` to `add-org` (leave them out for
Bitwarden Cloud, which is the default):

```bash
sudo bash vault-event-monitor.sh add-org \
  --name "Acme Self-Hosted" \
  --client-id "organization.yyyy" \
  --client-secret "yyyy" \
  --identity-url "https://bitwarden.acme.example.com/identity/connect/token" \
  --api-url "https://bitwarden.acme.example.com/api/public"
```

### Applying changes

`add-org`/`remove-org` take effect on the next scheduled run (every
minute, via cron), or immediately:

```bash
sudo bash vault-event-monitor.sh run-now
```

### Security

`organizations.json` contains secrets. It's created with `600`
permissions, owned by `root` - do not loosen this. Never commit a
filled-in copy to version control; only `organizations.json.example`
(placeholder values) is meant to be shared.

## What this integration created

| Path | Purpose |
|---|---|
| `/opt/scripts/bitwarden_wazuh_poller.py` | The poller itself |
| `/etc/bitwarden-wazuh/organizations.json` | Your real credentials (secret) |
| `/etc/bitwarden-wazuh/organizations.json.example` | Documented template |
| `/var/log/bitwarden/events.log` | Collected events (monitored by Wazuh) |
| `/var/log/bitwarden/poller.log` | Poller's own run log (cron output) |
| `/etc/cron.d/bitwarden-wazuh` | Schedules the poller every minute |
| `/var/ossec/etc/ossec.conf` | `<localfile>` block added (marked) |
| `/var/ossec/etc/rules/local_rules.xml` | 45 detection rules added (IDs 100250-100294, marked) |

## Verifying it works

```bash
sudo bash vault-event-monitor.sh status
sudo tail -f /var/log/bitwarden/poller.log
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep '"description":"Bitwarden: '
```

## Uninstalling

```bash
sudo bash vault-event-monitor.sh uninstall
```
README_EOF
  chmod 644 "${README_FILE}"
}

set_permissions() {
  chown root:root "${POLLER_SCRIPT}" "${ORGS_EXAMPLE}" "${README_FILE}" 2>/dev/null || true
  [[ -f "${ORGS_CONFIG}" ]] && chmod 600 "${ORGS_CONFIG}" && chown root:root "${ORGS_CONFIG}"

  if getent group "${WAZUH_GROUP}" &>/dev/null; then
    chgrp "${WAZUH_GROUP}" "${LOG_DIR}"
    chmod 2750 "${LOG_DIR}"
  else
    chmod 750 "${LOG_DIR}"
    echo "Warning: group '${WAZUH_GROUP}' not found - ${LOG_DIR} left root-only." >&2
    echo "Once your Wazuh service account exists, run:" >&2
    echo "  chgrp ${WAZUH_GROUP} ${LOG_DIR} && chmod 2750 ${LOG_DIR}" >&2
  fi
}

ensure_python_deps() {
  if ! python3 -c "import requests" &>/dev/null; then
    echo "    'requests' not found, installing..."
    python3 -m pip install requests --break-system-packages 2>/dev/null \
      || python3 -m pip install requests
  fi
}

write_cron_job() {
  cat > "${CRON_FILE}" <<EOF
${CRON_SCHEDULE} root /usr/bin/python3 ${POLLER_SCRIPT} >> ${LOG_DIR}/poller.log 2>&1
EOF
  chmod 644 "${CRON_FILE}"
}

selinux_restore() {
  if command -v getenforce &>/dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
    restorecon -Rv /etc/cron.d/ "${CONFIG_DIR}" "${LOG_DIR}" "${SCRIPT_DIR}" 2>/dev/null || true
  fi
}
# ==============================================================================
# Wazuh configuration functions (ossec.conf localfile + local_rules.xml rules)
# ==============================================================================
# Design: both blocks are always removed-then-reinserted fresh on every
# install/update run (rather than "skip if already present"). This makes
# re-running install, or running update, reliably pick up rule/config
# changes shipped in a newer version of this script - the exact problem
# that motivated adding the "update" command in the first place.

# Removes a marker-delimited block from a file in place, if both markers
# are present. Leaves the file untouched otherwise. Safe to call on a
# file that doesn't contain the block at all.
remove_marked_block() {
  local file="$1" begin_marker="$2" end_marker="$3"
  if [[ -f "${file}" ]] && grep -qF "${begin_marker}" "${file}"; then
    python3 - "${file}" "${begin_marker}" "${end_marker}" <<'PYEOF'
import sys

path, begin_marker, end_marker = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, "r") as f:
    content = f.read()

start = content.find(begin_marker)
end = content.find(end_marker)
if start == -1 or end == -1:
    sys.exit(0)
end += len(end_marker)

new_content = content[:start].rstrip() + "\n" + content[end:].lstrip("\n")

with open(path, "w") as f:
    f.write(new_content)
PYEOF
  fi
}

insert_localfile_block() {
  python3 - "${OSSEC_CONF}" "${LOG_DIR}/events.log" <<'PYEOF'
import sys

conf_path, log_path = sys.argv[1], sys.argv[2]
block = f"""  <!-- BEGIN bitwarden-wazuh-localfile -->
  <localfile>
    <log_format>json</log_format>
    <location>{log_path}</location>
  </localfile>
  <!-- END bitwarden-wazuh-localfile -->
"""

with open(conf_path, "r") as f:
    content = f.read()

marker = "</ossec_config>"
idx = content.rfind(marker)
if idx == -1:
    sys.exit("No </ossec_config> closing tag found - aborting.")

with open(conf_path, "w") as f:
    f.write(content[:idx] + block + content[idx:])
PYEOF
}

check_rules_id_collisions() {
  # Excludes local_rules.xml's own current content on purpose: we always
  # call this AFTER remove_marked_block has already stripped any previous
  # bitwarden-wazuh-rules block out of it, so anything found here is a
  # genuine collision with something else.
  local conflicts
  conflicts=$(grep -rhoE "${RULES_ID_PATTERN}" /var/ossec/ruleset/rules/*.xml /var/ossec/etc/rules/*.xml 2>/dev/null | sort -u || true)
  if [[ -n "${conflicts}" ]]; then
    echo "One or more rule IDs in the 100250-100294 range are already in use:" >&2
    echo "${conflicts}" >&2
    return 1
  fi
  return 0
}

insert_rules_block() {
  touch "${LOCAL_RULES}"
  cat >> "${LOCAL_RULES}" <<'RULES_EOF'

<!-- BEGIN bitwarden-wazuh-rules -->
<group name="bitwarden,">

  <rule id="100250" level="3">
    <decoded_as>json</decoded_as>
    <field name="_source" type="pcre2">^bitwarden$</field>
    <description>Bitwarden: event received</description>
  </rule>

  <!-- Authentication -->
  <rule id="100251" level="3">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1000$</field>
    <description>Bitwarden: user logged in (actingUserId: $(actingUserId))</description>
    <group>authentication_success,</group>
  </rule>

  <rule id="100252" level="5">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1005$</field>
    <description>Bitwarden: failed login - incorrect password (actingUserId: $(actingUserId), src_ip: $(ipAddress))</description>
    <group>authentication_failed,bitwarden_login_failed,</group>
  </rule>

  <rule id="100253" level="5">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1006$</field>
    <description>Bitwarden: failed login - incorrect two-step login (actingUserId: $(actingUserId), src_ip: $(ipAddress))</description>
    <group>authentication_failed,bitwarden_login_failed,</group>
  </rule>

  <rule id="100254" level="10" frequency="5" timeframe="120">
    <if_matched_group>bitwarden_login_failed</if_matched_group>
    <same_field>actingUserId</same_field>
    <description>Bitwarden: possible brute-force attempt - 5 failed logins within 2 minutes (actingUserId: $(actingUserId))</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,</group>
  </rule>

  <!-- Account security changes -->
  <rule id="100255" level="5">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1001$</field>
    <description>Bitwarden: user changed their account password (actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100256" level="8">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1003$</field>
    <description>Bitwarden: user turned OFF two-step login (actingUserId: $(actingUserId))</description>
    <group>2fa,</group>
  </rule>

  <rule id="100257" level="3">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1002$</field>
    <description>Bitwarden: user enabled two-step login (actingUserId: $(actingUserId))</description>
    <group>2fa,</group>
  </rule>

  <rule id="100258" level="8">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1008$</field>
    <description>Bitwarden: master password reset via account recovery (actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100259" level="5">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1009$</field>
    <description>Bitwarden: user migrated their decryption key with Key Connector (actingUserId: $(actingUserId))</description>
  </rule>

  <!-- Vault export / data exfiltration -->
  <rule id="100260" level="12">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1007$</field>
    <description>Bitwarden: user exported their individual vault items (actingUserId: $(actingUserId))</description>
    <group>data_loss,</group>
  </rule>

  <rule id="100261" level="12">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1602$</field>
    <description>Bitwarden: organization vault was exported (actingUserId: $(actingUserId))</description>
    <group>data_loss,</group>
  </rule>

  <rule id="100262" level="15">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1601$</field>
    <description>Bitwarden: organization vault was PURGED (actingUserId: $(actingUserId))</description>
    <group>data_loss,</group>
  </rule>

  <!-- Item events -->
  <rule id="100263" level="3">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1100$</field>
    <description>Bitwarden: item created (itemId: $(itemId), actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100264" level="3">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1101$</field>
    <description>Bitwarden: item edited (itemId: $(itemId), actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100265" level="8">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1102$</field>
    <description>Bitwarden: item permanently deleted (itemId: $(itemId), actingUserId: $(actingUserId))</description>
    <group>item_deletion,</group>
  </rule>

  <rule id="100266" level="5">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1115$</field>
    <description>Bitwarden: item sent to trash (itemId: $(itemId), actingUserId: $(actingUserId))</description>
    <group>item_deletion,</group>
  </rule>

  <rule id="100267" level="12" frequency="10" timeframe="300">
    <if_matched_group>item_deletion</if_matched_group>
    <same_field>actingUserId</same_field>
    <description>Bitwarden: possible mass deletion of vault items - 10+ deletions within 5 minutes (actingUserId: $(actingUserId))</description>
    <group>data_loss,</group>
  </rule>

  <!-- Sensitive field access (auditing, not necessarily malicious) -->
  <rule id="100268" level="3">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^(1108|1109|1110|1111|1112|1113|1117|1118)$</field>
    <description>Bitwarden: sensitive field viewed or copied - password/hidden field/security code (itemId: $(itemId), actingUserId: $(actingUserId))</description>
    <group>item_sensitive_access,</group>
  </rule>

  <!-- Organization membership -->
  <rule id="100269" level="5">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1500$</field>
    <description>Bitwarden: user invited to organization (actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100270" level="5">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1503$</field>
    <description>Bitwarden: user removed from organization (actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100271" level="5">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1511$</field>
    <description>Bitwarden: organization access revoked for a user (actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100272" level="5">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1512$</field>
    <description>Bitwarden: organization access restored for a user (actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100273" level="8">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1515$</field>
    <description>Bitwarden: user deleted from organization (actingUserId: $(actingUserId))</description>
  </rule>

  <!-- Organization / security settings -->
  <rule id="100274" level="8">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1600$</field>
    <description>Bitwarden: organization settings edited (actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100275" level="5">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1604$</field>
    <description>Bitwarden: SSO enabled for organization (actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100276" level="10">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1605$</field>
    <description>Bitwarden: SSO disabled for organization (actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100277" level="5">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1606$</field>
    <description>Bitwarden: Key Connector enabled for organization (actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100278" level="10">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1607$</field>
    <description>Bitwarden: Key Connector disabled for organization (actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100279" level="10">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^1700$</field>
    <description>Bitwarden: enterprise policy modified (actingUserId: $(actingUserId))</description>
  </rule>

  <!-- Claimed domains -->
  <rule id="100280" level="5">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^(2000|2001)$</field>
    <description>Bitwarden: claimed domain added or removed (actingUserId: $(actingUserId))</description>
  </rule>

  <!-- Secrets Manager -->
  <rule id="100281" level="8">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^2103$</field>
    <description>Bitwarden: Secrets Manager secret deleted (actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100282" level="8">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^2203$</field>
    <description>Bitwarden: Secrets Manager project deleted (actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100283" level="5">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^2305$</field>
    <description>Bitwarden: Secrets Manager machine account deleted (actingUserId: $(actingUserId))</description>
  </rule>

  <!-- Bitwarden Send -->
  <rule id="100284" level="3">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^(2501|2502|2503|2504|2505)$</field>
    <description>Bitwarden: Send created (actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100285" level="3">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^(2508|2509)$</field>
    <description>Bitwarden: Send deleted (actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100286" level="3">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^(2510|2511)$</field>
    <description>Bitwarden: Send accessed (actingUserId: $(actingUserId))</description>
  </rule>

  <!-- ============================================================= -->
  <!-- "Rest" categories: every other officially documented Bitwarden -->
  <!-- event type (bitwarden.com/help/event-logs) that doesn't warrant -->
  <!-- its own dedicated rule above, grouped by area, so the generic  -->
  <!-- "Bitwarden: event received" fallback (100250) is now only seen -->
  <!-- for event types Bitwarden documents in the future.             -->
  <!-- ============================================================= -->

  <rule id="100287" level="3">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^(1103|1104|1105|1106|1107|1114|1116)$</field>
    <description>Bitwarden: item interaction (type $(type), itemId: $(itemId), actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100288" level="3">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^(1300|1301|1302)$</field>
    <description>Bitwarden: collection event (type $(type), actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100289" level="3">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^(1400|1401|1402)$</field>
    <description>Bitwarden: group event (type $(type), actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100290" level="3">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^(1004|1010|1011)$</field>
    <description>Bitwarden: account event (type $(type), actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100291" level="5">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^(1501|1502|1504|1505|1506|1507|1508|1509|1510|1513|1514|1516|1517|1518|1519)$</field>
    <description>Bitwarden: organization membership event (type $(type), actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100292" level="5">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^(1603|1608|1609|1610|1611|1612|1613|1614|1615|1616|1617|1618|1619|1620|1621|1622|1623|2002|2003)$</field>
    <description>Bitwarden: organization settings event (type $(type), actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100293" level="3">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^(2100|2101|2102|2200|2201|2202|2300|2301|2302|2303|2304)$</field>
    <description>Bitwarden: Secrets Manager event (type $(type), actingUserId: $(actingUserId))</description>
  </rule>

  <rule id="100294" level="3">
    <if_sid>100250</if_sid>
    <field name="type" type="pcre2">^(2506|2507)$</field>
    <description>Bitwarden: Send edited (type $(type), actingUserId: $(actingUserId))</description>
  </rule>

</group>
<!-- END bitwarden-wazuh-rules -->
RULES_EOF
}

# Refreshes both Wazuh config blocks (used by both install and update):
# backs up, removes any previous block, checks for ID collisions, inserts
# fresh, validates, and restarts - rolling back both files on failure.
# Returns 0 on success, 1 on failure (with backups already restored).
refresh_wazuh_config() {
  local ts ossec_backup rules_backup

  ts="$(date +%Y%m%d%H%M%S)"
  ossec_backup="${OSSEC_CONF}.bak.${ts}"
  rules_backup="${LOCAL_RULES}.bak.${ts}"

  cp -p "${OSSEC_CONF}" "${ossec_backup}"
  touch "${LOCAL_RULES}"
  cp -p "${LOCAL_RULES}" "${rules_backup}"

  remove_marked_block "${OSSEC_CONF}" "${LOCALFILE_BEGIN}" "${LOCALFILE_END}"
  remove_marked_block "${LOCAL_RULES}" "${RULES_BEGIN}" "${RULES_END}"

  if ! check_rules_id_collisions; then
    echo "Aborting without changing anything further. Resolve the conflict and re-run." >&2
    cp -p "${ossec_backup}" "${OSSEC_CONF}"
    cp -p "${rules_backup}" "${LOCAL_RULES}"
    return 1
  fi

  insert_localfile_block
  insert_rules_block

  if ! /var/ossec/bin/wazuh-logcollector -t || ! /var/ossec/bin/wazuh-analysisd -t; then
    echo "Configuration test failed! Restoring both backups." >&2
    cp -p "${ossec_backup}" "${OSSEC_CONF}"
    cp -p "${rules_backup}" "${LOCAL_RULES}"
    return 1
  fi

  systemctl restart wazuh-manager
  sleep 3
  echo "Backups (only needed if something looks wrong): ${ossec_backup}, ${rules_backup}"
  return 0
}
# ==============================================================================
# Organization management functions
# ==============================================================================

# add_org_engine NAME CLIENT_ID CLIENT_SECRET [IDENTITY_URL] [API_URL]
add_org_engine() {
  local name="$1" client_id="$2" client_secret="$3" identity_url="${4:-}" api_url="${5:-}"
  python3 - "${ORGS_CONFIG}" "${name}" "${client_id}" "${client_secret}" "${identity_url}" "${api_url}" <<'PYEOF'
import json
import os
import sys

path, name, client_id, client_secret, identity_url, api_url = sys.argv[1:7]

if os.path.exists(path):
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, list):
        data = []
else:
    data = []

for entry in data:
    if "_comment" in entry:
        continue
    if entry.get("name") == name:
        sys.exit(f"An organization named '{name}' already exists in {path}.")

new_entry = {"name": name, "client_id": client_id, "client_secret": client_secret}
if identity_url:
    new_entry["identity_url"] = identity_url
if api_url:
    new_entry["api_url"] = api_url

real = [e for e in data if "_comment" not in e]
comments = [e for e in data if "_comment" in e]
new_data = real + [new_entry] + comments

with open(path, "w") as f:
    json.dump(new_data, f, indent=2)
    f.write("\n")

print(f"Added organization '{name}'.")
PYEOF
  local status=$?
  if [[ ${status} -eq 0 ]]; then
    chmod 600 "${ORGS_CONFIG}"
    chown root:root "${ORGS_CONFIG}"
  fi
  return ${status}
}

# remove_org_engine NAME
remove_org_engine() {
  local name="$1"

  if [[ ! -f "${ORGS_CONFIG}" ]]; then
    echo "${ORGS_CONFIG} does not exist - nothing to remove." >&2
    return 1
  fi

  python3 - "${ORGS_CONFIG}" "${name}" <<'PYEOF'
import json
import sys

path, name = sys.argv[1], sys.argv[2]
with open(path) as f:
    data = json.load(f)

real = [e for e in data if "_comment" not in e]
names = [e.get("name") for e in real]
if name not in names:
    avail = ", ".join(names) if names else "(none)"
    sys.exit(f"No organization named '{name}' found. Configured: {avail}")

new_data = [e for e in data if "_comment" in e or e.get("name") != name]
with open(path, "w") as f:
    json.dump(new_data, f, indent=2)
    f.write("\n")

print(f"Removed organization '{name}' from {path}.")
PYEOF
  local status=$?
  [[ ${status} -eq 0 ]] || return ${status}

  # Also clean up that organization's leftover state/cache files, using
  # the deployed poller's own slugify() so the slug always matches
  # exactly what the poller itself would have used.
  if [[ -f "${POLLER_SCRIPT}" ]]; then
    python3 - "${POLLER_SCRIPT}" "${LOG_DIR}" "${name}" <<'PYEOF'
import importlib.util
import os
import sys

poller_path, log_dir, name = sys.argv[1], sys.argv[2], sys.argv[3]

spec = importlib.util.spec_from_file_location("bwp", poller_path)
bwp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bwp)

slug = bwp.slugify(name)
for suffix in (f".last_run.{slug}", f".members_cache.{slug}.json"):
    p = os.path.join(log_dir, suffix)
    if os.path.exists(p):
        os.remove(p)
        print(f"Removed leftover state file: {p}")
PYEOF
  fi
  return 0
}

# Prints "N|Name|masked_client_id" for each real (non-comment) organization.
list_orgs() {
  [[ -f "${ORGS_CONFIG}" ]] || return 0
  python3 - "${ORGS_CONFIG}" <<'PYEOF'
import json
import sys

path = sys.argv[1]
with open(path) as f:
    data = json.load(f)

i = 0
for entry in data:
    if "_comment" in entry:
        continue
    i += 1
    cid = entry.get("client_id", "")
    masked = cid[:18] + "..." if len(cid) > 18 else cid
    print(f"{i}|{entry.get('name', '')}|{masked}")
PYEOF
}

org_count() {
  list_orgs | grep -c '.' || true
}

# Interactively prompts for one organization's details and adds it.
# Returns the organization name via the global LAST_ADDED_ORG_NAME, or
# returns non-zero if the user cancelled.
prompt_for_org_and_add() {
  local name client_id client_secret is_self_hosted identity_url="" api_url=""

  read -r -p "Organization name: " name
  if [[ -z "${name}" ]]; then
    echo "Organization name cannot be empty - cancelled." >&2
    return 1
  fi

  read -r -p "Client ID (starts with 'organization.'): " client_id
  read -r -s -p "Client secret: " client_secret
  echo
  if [[ -z "${client_id}" || -z "${client_secret}" ]]; then
    echo "Client ID and secret are required - cancelled." >&2
    return 1
  fi

  if prompt_yes_no "Is this a self-hosted Bitwarden instance?" "n"; then
    read -r -p "Identity URL (e.g. https://bitwarden.example.com/identity/connect/token): " identity_url
    read -r -p "API URL (e.g. https://bitwarden.example.com/api/public): " api_url
  fi

  if add_org_engine "${name}" "${client_id}" "${client_secret}" "${identity_url}" "${api_url}"; then
    LAST_ADDED_ORG_NAME="${name}"
    return 0
  fi
  return 1
}
# ==============================================================================
# Top-level commands
# ==============================================================================

print_final_summary() {
  cat <<EOF

==============================================================================
Done.

Verification:
  sudo bash "\$0" status
  sudo tail -f ${LOG_DIR}/poller.log
  sudo tail -f /var/ossec/logs/alerts/alerts.json | grep '"description":"Bitwarden: '

Full documentation: ${README_FILE}
==============================================================================
EOF
}

# do_install [NAME] [CLIENT_ID] [CLIENT_SECRET] [IDENTITY_URL] [API_URL]
do_install() {
  local name="${1:-}" client_id="${2:-}" client_secret="${3:-}" identity_url="${4:-}" api_url="${5:-}"
  local org_configured=0

  echo "=== Installing Bitwarden -> Wazuh integration ==="
  echo
  echo "Setting up files and permissions..."
  ensure_directories
  write_poller_script
  ensure_config_scaffolding
  set_permissions
  ensure_python_deps
  write_cron_job
  selinux_restore

  echo "Setting up the Wazuh <localfile> entry and detection rules..."
  if ! refresh_wazuh_config; then
    echo "Installation aborted due to the error above." >&2
    return 1
  fi
  echo "Infrastructure installed."

  if [[ -n "${name}" ]]; then
    if [[ -z "${client_id}" || -z "${client_secret}" ]]; then
      echo "Incomplete organization flags (need --client-id and --client-secret too) - skipping organization setup." >&2
    elif add_org_engine "${name}" "${client_id}" "${client_secret}" "${identity_url}" "${api_url}"; then
      org_configured=1
    fi
  elif is_tty; then
    echo
    if prompt_yes_no "Would you like to configure your first Bitwarden organization now?" "y"; then
      while true; do
        if prompt_for_org_and_add; then
          echo "Added '${LAST_ADDED_ORG_NAME}'."
          org_configured=1
        fi
        prompt_yes_no "Add another organization?" "n" || break
      done
    fi
  else
    echo
    echo "No organization configured yet (non-interactive run, none given via flags)."
    echo "Add one with: sudo bash \$0 add-org --name NAME --client-id ID --client-secret SECRET"
  fi

  if [[ "${org_configured}" -eq 1 ]] && is_tty; then
    echo
    if prompt_yes_no "Run the poller now to test it?" "y"; then
      do_run_now
    fi
  fi

  print_final_summary
}

do_update() {
  require_installed || return 1
  echo "=== Updating poller script and Wazuh configuration ==="
  echo "(organizations.json is never touched by this)"
  echo
  write_poller_script
  ensure_config_scaffolding
  set_permissions
  ensure_python_deps
  write_cron_job
  selinux_restore

  if ! refresh_wazuh_config; then
    echo "Update aborted due to the error above." >&2
    return 1
  fi
  echo "Update complete."
}

do_run_now() {
  require_installed || return 1
  echo "=== Running the poller now ==="
  python3 "${POLLER_SCRIPT}"
}

do_status() {
  echo "=== Bitwarden -> Wazuh Integration Status ==="
  echo

  if is_installed; then
    echo "Poller script:    installed (${POLLER_SCRIPT})"
  else
    echo "Poller script:    NOT installed"
  fi

  if [[ -f "${CRON_FILE}" ]]; then
    echo "Cron job:         installed ($(awk '{print $1,$2,$3,$4,$5}' "${CRON_FILE}"))"
  else
    echo "Cron job:         NOT installed"
  fi

  if [[ -f "${OSSEC_CONF}" ]] && grep -qF "${LOCALFILE_BEGIN}" "${OSSEC_CONF}" 2>/dev/null; then
    echo "Wazuh localfile:  installed"
  else
    echo "Wazuh localfile:  NOT installed"
  fi

  if [[ -f "${LOCAL_RULES}" ]] && grep -qF "${RULES_BEGIN}" "${LOCAL_RULES}" 2>/dev/null; then
    local count
    count=$(grep -cE "${RULES_ID_PATTERN}" "${LOCAL_RULES}" 2>/dev/null || echo 0)
    echo "Wazuh rules:      installed (${count} rules)"
  else
    echo "Wazuh rules:      NOT installed"
  fi

  if command -v systemctl &>/dev/null; then
    if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
      echo "Wazuh manager:    active"
    else
      echo "Wazuh manager:    not active"
    fi
  fi

  echo
  echo "Configured organizations:"
  if [[ -f "${POLLER_SCRIPT}" && -f "${ORGS_CONFIG}" ]]; then
    python3 - "${POLLER_SCRIPT}" "${ORGS_CONFIG}" <<'PYEOF'
import importlib.util
import os
import sys
from datetime import datetime, timezone

poller_path, orgs_config = sys.argv[1], sys.argv[2]

spec = importlib.util.spec_from_file_location("bwp", poller_path)
bwp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bwp)
bwp.ORGS_CONFIG_FILE = orgs_config

try:
    orgs = bwp.load_organizations()
except SystemExit as e:
    print(f"  (could not read configuration: {e})")
    orgs = []

if not orgs:
    print("  (none configured yet)")
else:
    now = datetime.now(timezone.utc)
    for org in orgs:
        cid = org["client_id"]
        masked = cid[:18] + "..." if len(cid) > 18 else cid
        if os.path.exists(org["state_file"]):
            with open(org["state_file"]) as f:
                ts = f.read().strip()
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                age_min = (now - dt).total_seconds() / 60
                last_run = f"{age_min:.0f} min ago"
            except ValueError:
                last_run = ts
        else:
            last_run = "never run yet"
        print(f"  - {org['name']}  ({masked})  - last poll: {last_run}")
PYEOF
  else
    echo "  (none configured yet)"
  fi

  echo
  if [[ -f "${LOG_DIR}/events.log" ]]; then
    echo "Events log: ${LOG_DIR}/events.log ($(wc -l < "${LOG_DIR}/events.log" 2>/dev/null || echo 0) lines)"
  fi
}

# do_uninstall FORCE(0|1)
do_uninstall() {
  local force="${1:-0}"

  if [[ "${force}" -ne 1 ]]; then
    if ! is_tty; then
      echo "Refusing to uninstall non-interactively without --force." >&2
      return 1
    fi
    cat <<EOF
This will permanently remove:
  - ${POLLER_SCRIPT}
  - ${CONFIG_DIR}/  (including organizations.json - YOUR REAL BITWARDEN SECRETS)
  - ${LOG_DIR}/     (collected events, state, caches)
  - ${CRON_FILE}
  - The <localfile> block in ${OSSEC_CONF}
  - The 45 detection rules (IDs 100250-100294) in ${LOCAL_RULES}

The Wazuh manager will be restarted afterwards.
Not removed: the Python 'requests' module.

EOF
    local confirmation
    read -r -p "Type 'DELETE' to confirm: " confirmation
    if [[ "${confirmation}" != "DELETE" ]]; then
      echo "Aborted, nothing was changed."
      return 1
    fi
  fi

  echo
  echo "Removing cron job..."
  rm -f "${CRON_FILE}"

  echo "Removing poller script..."
  rm -f "${POLLER_SCRIPT}"
  rm -rf "${SCRIPT_DIR}/__pycache__"
  rmdir --ignore-fail-on-non-empty "${SCRIPT_DIR}" 2>/dev/null || true

  echo "Removing config directory (including organizations.json)..."
  rm -rf "${CONFIG_DIR}"

  echo "Removing log/state directory..."
  rm -rf "${LOG_DIR}"

  echo "Reverting ossec.conf..."
  remove_marked_block "${OSSEC_CONF}" "${LOCALFILE_BEGIN}" "${LOCALFILE_END}"

  echo "Reverting local_rules.xml..."
  remove_marked_block "${LOCAL_RULES}" "${RULES_BEGIN}" "${RULES_END}"

  echo "Validating the reverted configuration..."
  if [[ -x /var/ossec/bin/wazuh-logcollector ]] && [[ -x /var/ossec/bin/wazuh-analysisd ]]; then
    /var/ossec/bin/wazuh-logcollector -t || echo "Warning: logcollector validation reported problems." >&2
    /var/ossec/bin/wazuh-analysisd -t || echo "Warning: analysisd validation reported problems." >&2
  fi

  if command -v systemctl &>/dev/null && systemctl list-unit-files 2>/dev/null | grep -q wazuh-manager; then
    echo "Restarting wazuh-manager..."
    systemctl restart wazuh-manager
    sleep 3
  fi

  echo
  echo "Uninstall complete."
}

# ==============================================================================
# Interactive menu
# ==============================================================================

menu_remove_org() {
  require_installed || return
  local orgs_list
  orgs_list="$(list_orgs)"
  if [[ -z "${orgs_list}" ]]; then
    echo "No organizations configured yet."
    return
  fi

  echo "Currently configured organizations:"
  echo "${orgs_list}" | awk -F'|' '{printf "  %s) %s  (%s)\n", $1, $2, $3}'

  local choice name
  read -r -p "Which one do you want to remove? [number, or 'c' to cancel]: " choice
  if [[ "${choice}" == "c" || -z "${choice}" ]]; then
    echo "Cancelled."
    return
  fi
  name="$(echo "${orgs_list}" | awk -F'|' -v n="${choice}" '$1==n {print $2}')"
  if [[ -z "${name}" ]]; then
    echo "Not a valid choice." >&2
    return
  fi

  if prompt_yes_no "Remove '${name}'? This also deletes its cached state." "n"; then
    remove_org_engine "${name}"
  else
    echo "Cancelled."
  fi
}

interactive_menu() {
  local choice
  while true; do
    echo
    echo "=== Bitwarden -> Wazuh Integration ==="
    echo "1) Install integration (default)"
    echo "2) Add an organization"
    echo "3) Remove an organization"
    echo "4) Show status"
    echo "5) Run the poller now (test)"
    echo "6) Update rules & configuration"
    echo "7) Uninstall integration"
    echo "8) Exit"
    read -r -p "Choose an option [1]: " choice
    choice="${choice:-1}"
    echo

    case "${choice}" in
      1) do_install ;;
      2)
        if require_installed; then
          if prompt_for_org_and_add; then
            echo "Added '${LAST_ADDED_ORG_NAME}'."
            if prompt_yes_no "Run the poller now to test it?" "y"; then
              do_run_now
            fi
          fi
        fi
        ;;
      3) menu_remove_org ;;
      4) do_status ;;
      5) do_run_now ;;
      6) do_update ;;
      7) do_uninstall 0 ;;
      8) echo "Bye."; break ;;
      *) echo "Unknown option: ${choice}" ;;
    esac
  done
}

# ==============================================================================
# CLI flag parsing / non-interactive commands
# ==============================================================================

parse_org_flags() {
  ARG_NAME="" ARG_CLIENT_ID="" ARG_CLIENT_SECRET="" ARG_IDENTITY_URL="" ARG_API_URL=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --name) ARG_NAME="${2:-}"; shift 2 ;;
      --client-id) ARG_CLIENT_ID="${2:-}"; shift 2 ;;
      --client-secret) ARG_CLIENT_SECRET="${2:-}"; shift 2 ;;
      --identity-url) ARG_IDENTITY_URL="${2:-}"; shift 2 ;;
      --api-url) ARG_API_URL="${2:-}"; shift 2 ;;
      *) echo "Unknown option: $1" >&2; return 1 ;;
    esac
  done
  return 0
}

cmd_install() {
  if ! parse_org_flags "$@"; then
    print_help
    exit 1
  fi
  do_install "${ARG_NAME}" "${ARG_CLIENT_ID}" "${ARG_CLIENT_SECRET}" "${ARG_IDENTITY_URL}" "${ARG_API_URL}"
}

cmd_add_org() {
  if ! parse_org_flags "$@"; then
    print_help
    exit 1
  fi
  if [[ -z "${ARG_NAME}" || -z "${ARG_CLIENT_ID}" || -z "${ARG_CLIENT_SECRET}" ]]; then
    echo "add-org requires --name, --client-id, and --client-secret." >&2
    exit 1
  fi
  require_installed || exit 1
  add_org_engine "${ARG_NAME}" "${ARG_CLIENT_ID}" "${ARG_CLIENT_SECRET}" "${ARG_IDENTITY_URL}" "${ARG_API_URL}"
}

cmd_remove_org() {
  if ! parse_org_flags "$@"; then
    print_help
    exit 1
  fi
  if [[ -z "${ARG_NAME}" ]]; then
    echo "remove-org requires --name." >&2
    exit 1
  fi
  require_installed || exit 1
  remove_org_engine "${ARG_NAME}"
}

cmd_uninstall() {
  local force=0
  for arg in "$@"; do
    [[ "${arg}" == "--force" || "${arg}" == "-f" ]] && force=1
  done
  do_uninstall "${force}"
}

print_help() {
  cat <<'EOF'
Bitwarden -> Wazuh integration

Interactive use (recommended for first-time setup):
  sudo bash vault-event-monitor.sh

Non-interactive use:
  sudo bash vault-event-monitor.sh install [--name NAME --client-id ID --client-secret SECRET [--identity-url URL] [--api-url URL]]
  sudo bash vault-event-monitor.sh add-org --name NAME --client-id ID --client-secret SECRET [--identity-url URL] [--api-url URL]
  sudo bash vault-event-monitor.sh remove-org --name NAME
  sudo bash vault-event-monitor.sh status
  sudo bash vault-event-monitor.sh run-now
  sudo bash vault-event-monitor.sh update
  sudo bash vault-event-monitor.sh uninstall [--force]
  sudo bash vault-event-monitor.sh help

Examples:
  sudo bash vault-event-monitor.sh install --name "Acme Corp" --client-id "organization.xxxx" --client-secret "xxxx"
  sudo bash vault-event-monitor.sh add-org --name "Acme NL" --client-id "organization.yyyy" --client-secret "yyyy"
  sudo bash vault-event-monitor.sh remove-org --name "Acme NL"
  sudo bash vault-event-monitor.sh uninstall --force
EOF
}

# ==============================================================================
# Entry point
# ==============================================================================

main() {
  local command="${1:-}"

  if [[ "${command}" == "help" || "${command}" == "-h" || "${command}" == "--help" ]]; then
    print_help
    exit 0
  fi

  require_root
  require_wazuh_manager

  if [[ -z "${command}" ]]; then
    if is_tty; then
      interactive_menu
    else
      echo "No command given and no interactive terminal detected." >&2
      print_help
      exit 1
    fi
    exit 0
  fi

  shift
  case "${command}" in
    install) cmd_install "$@" ;;
    add-org) cmd_add_org "$@" ;;
    remove-org) cmd_remove_org "$@" ;;
    status) do_status ;;
    run-now) do_run_now ;;
    update) do_update ;;
    uninstall) cmd_uninstall "$@" ;;
    *)
      echo "Unknown command: ${command}" >&2
      print_help
      exit 1
      ;;
  esac
}

main "$@"

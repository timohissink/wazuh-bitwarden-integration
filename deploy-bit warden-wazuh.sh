#!/usr/bin/env bash
# ==============================================================================
# Bitwarden -> Wazuh integration: complete deployment script
# ==============================================================================
# Deploys the full pipeline on a Wazuh manager host:
#
#   Bitwarden Public API (one or more orgs)
#     -> Python poller (with member-email enrichment)
#     -> /var/log/bitwarden/events.log
#     -> Wazuh <localfile>
#     -> 37 custom detection rules
#     -> Wazuh alerts
#
# Designed to be run by anyone, on any Wazuh manager, with the same result:
#   - Idempotent: safe to re-run. Already-completed steps are skipped.
#   - Does not overwrite an existing organizations.json (your real secrets).
#   - Does not depend on any specific human user account - only on the
#     standard "wazuh" service account/group that every Wazuh install creates.
#
# Prerequisites:
#   - A working Wazuh manager (this script does NOT install Wazuh itself)
#   - Root / sudo access
#   - Outbound HTTPS access to Bitwarden's API (or your self-hosted instance)
#   - At least one Bitwarden organization on a Teams or Enterprise plan,
#     with an organization API key (see the generated README.md for how
#     to obtain one)
#
# Usage:
#   sudo bash deploy-bitwarden-wazuh.sh
#
# After running, edit /etc/bitwarden-wazuh/organizations.json with your
# real Bitwarden organization credentials - see that step's output, and
# /etc/bitwarden-wazuh/README.md, for details.
# ==============================================================================

set -euo pipefail

# --- Paths --------------------------------------------------------------------
SCRIPT_DIR="/opt/scripts"
POLLER_SCRIPT="${SCRIPT_DIR}/bitwarden_wazuh_poller.py"

CONFIG_DIR="/etc/bitwarden-wazuh"
ORGS_CONFIG="${CONFIG_DIR}/organizations.json"
ORGS_EXAMPLE="${CONFIG_DIR}/organizations.json.example"
README_FILE="${CONFIG_DIR}/README.md"

LOG_DIR="/var/log/bitwarden"
CRON_FILE="/etc/cron.d/bitwarden-wazuh"
CRON_SCHEDULE="*/5 * * * *"

OSSEC_CONF="/var/ossec/etc/ossec.conf"
LOCAL_RULES="/var/ossec/etc/rules/local_rules.xml"

WAZUH_GROUP="wazuh"   # standard service account group created by every Wazuh install

OSSEC_BACKUP="${OSSEC_CONF}.bak.$(date +%Y%m%d%H%M%S)"
RULES_BACKUP="${LOCAL_RULES}.bak.$(date +%Y%m%d%H%M%S)"

LOCALFILE_MARKER="BEGIN bitwarden-wazuh-localfile"
RULES_MARKER="BEGIN bitwarden-wazuh-rules"
RULES_ID_PATTERN='id="1002[5-8][0-9]"'   # covers 100250-100289 (our IDs: 100250-100286)
# ------------------------------------------------------------------------------

STEP=0
TOTAL_STEPS=13
step() {
  STEP=$((STEP + 1))
  echo
  echo "==> [${STEP}/${TOTAL_STEPS}] $1"
}

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script must be run as root (or via sudo)." >&2
  exit 1
fi

step "Checking prerequisites"
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
echo "    OK: Wazuh manager binaries and python3 found."

step "Creating directories"
mkdir -p "${SCRIPT_DIR}" "${CONFIG_DIR}" "${LOG_DIR}"
echo "    ${SCRIPT_DIR}"
echo "    ${CONFIG_DIR}"
echo "    ${LOG_DIR}"

step "Deploying the poller script"
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
root-owned with 600 permissions, just like the old single-org env file.

Requires: pip install requests
Run this periodically via cron, e.g. every 5 minutes.
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
# every 5-minute poll. Applies to every organization.
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
echo "    ${POLLER_SCRIPT}"

step "Setting up the organizations configuration"
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
echo "    ${ORGS_EXAMPLE} (reference template, always kept up to date)"

if [[ -f "${ORGS_CONFIG}" ]]; then
  echo "    ${ORGS_CONFIG} already exists - leaving your existing configuration untouched."
else
  cat > "${ORGS_CONFIG}" <<'ORGS_EOF'
[
  {
    "name": "REPLACE_WITH_YOUR_ORGANIZATION_NAME",
    "client_id": "organization.00000000-0000-0000-0000-000000000000",
    "client_secret": "REPLACE_WITH_YOUR_CLIENT_SECRET"
  },
  {
    "_comment": "To monitor a second organization, add another object here (separated by a comma from the block above), e.g.: { \"name\": \"Second Org\", \"client_id\": \"organization.11111111-1111-1111-1111-111111111111\", \"client_secret\": \"...\" } - as many as you need. Entries with a _comment key, like this one, are just documentation and are always ignored."
  }
]
ORGS_EOF
  echo "    Created a PLACEHOLDER ${ORGS_CONFIG} with one example organization"
  echo "    plus a '_comment' entry showing how to add more (see the file itself)."
  echo "    *** You must edit this file with your real Bitwarden credentials. ***"
  echo "    See ${README_FILE} for how to obtain a client_id/client_secret."
fi
chmod 600 "${ORGS_CONFIG}"
chown root:root "${ORGS_CONFIG}"

cat > "${README_FILE}" <<'README_EOF'
# Bitwarden -> Wazuh integration

This integration polls Bitwarden's organization Event Logs (via the
Bitwarden Public API) for one or more organizations, resolves actor/member
GUIDs to email addresses where possible, and feeds the result into this
Wazuh manager as JSON alerts.

## Configuring organizations

Edit `/etc/bitwarden-wazuh/organizations.json` - a JSON array, one object
per organization:

```json
[
  {
    "name": "Acme Corp",
    "client_id": "organization.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  }
]
```

### Getting a client_id / client_secret

1. Log in to the Bitwarden web vault as an organization Owner/Admin
   (requires a Teams or Enterprise plan).
2. Open the Admin Console -> **Settings** -> **Organization info** ->
   **API Key**, and view (or rotate) the key.
3. Copy the `client_id` (starts with `organization.`) and the
   `client_secret` into a new entry in `organizations.json`.

### Adding more organizations

Just add another object to the array - each one is polled and processed
independently. A failure in one organization (e.g. a revoked key) does
not block the others:

```json
[
  { "name": "Acme Corp", "client_id": "...", "client_secret": "..." },
  { "name": "Acme NL",   "client_id": "...", "client_secret": "..." }
]
```

### Documenting the file without breaking it

Plain JSON has no comment syntax. If you want to leave a note inside
`organizations.json` itself (for example, showing a colleague how to add
another organization), add an entry with only a `_comment` key - it's
always skipped, never treated as a real organization:

```json
{ "_comment": "Add another organization here, like the one above." }
```

The placeholder file created by the deploy script already includes one
of these by default.

### Self-hosted Bitwarden

Add `identity_url` and `api_url` to that organization's entry (leave
them out for Bitwarden Cloud, which is the default):

```json
{
  "name": "Acme Self-Hosted",
  "client_id": "organization.yyyy...",
  "client_secret": "yyyy...",
  "identity_url": "https://bitwarden.acme.example.com/identity/connect/token",
  "api_url": "https://bitwarden.acme.example.com/api/public"
}
```

### Applying changes

Changes to `organizations.json` take effect on the next scheduled run
(every 5 minutes, via cron), or immediately:

```bash
sudo python3 /opt/scripts/bitwarden_wazuh_poller.py
```

### Security

This file contains secrets. It's created with `600` permissions, owned
by `root` - do not loosen this. Never commit a filled-in
`organizations.json` to version control; only `organizations.json.example`
is meant to be shared/committed.

## What this deployment created

| Path | Purpose |
|---|---|
| `/opt/scripts/bitwarden_wazuh_poller.py` | The poller itself |
| `/etc/bitwarden-wazuh/organizations.json` | Your real credentials (secret, not overwritten on re-deploy) |
| `/etc/bitwarden-wazuh/organizations.json.example` | Documented template |
| `/var/log/bitwarden/events.log` | Collected events (monitored by Wazuh) |
| `/var/log/bitwarden/poller.log` | Poller's own run log (cron output) |
| `/etc/cron.d/bitwarden-wazuh` | Schedules the poller every 5 minutes |
| `/var/ossec/etc/ossec.conf` | `<localfile>` block added (marked, see below) |
| `/var/ossec/etc/rules/local_rules.xml` | 37 detection rules added (IDs 100250-100286, marked) |

Both Wazuh config changes are wrapped in `<!-- BEGIN/END bitwarden-wazuh-... -->`
marker comments, so they can be found and removed cleanly (see the
cleanup script) without disturbing the rest of your configuration.

## Verifying it works

```bash
sudo tail -f /var/log/bitwarden/poller.log
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep '"description":"Bitwarden: '
```

Or test a specific event directly against the rules:

```bash
sudo tail -1 /var/log/bitwarden/events.log | sudo /var/ossec/bin/wazuh-logtest 2>&1 | sed -n '/Phase 3/,$p'
```

## Uninstalling

Run `cleanup-bitwarden-wazuh.sh` from the same repository.
README_EOF
chmod 644 "${README_FILE}"
echo "    ${README_FILE}"

step "Setting permissions"
chown root:root "${POLLER_SCRIPT}" "${ORGS_EXAMPLE}" "${README_FILE}"
if getent group "${WAZUH_GROUP}" &>/dev/null; then
  chgrp "${WAZUH_GROUP}" "${LOG_DIR}"
  chmod 2750 "${LOG_DIR}"   # setgid: new files inherit the "wazuh" group automatically
  echo "    ${LOG_DIR} -> root:${WAZUH_GROUP}, 2750 (setgid, so Wazuh can read new logs)"
else
  chmod 750 "${LOG_DIR}"
  echo "    Warning: group '${WAZUH_GROUP}' not found - ${LOG_DIR} left root-only." >&2
  echo "    Once your Wazuh service account exists, run:" >&2
  echo "      chgrp ${WAZUH_GROUP} ${LOG_DIR} && chmod 2750 ${LOG_DIR}" >&2
fi

step "Checking Python dependencies"
if ! python3 -c "import requests" &>/dev/null; then
  echo "    'requests' not found, installing..."
  python3 -m pip install requests --break-system-packages 2>/dev/null \
    || python3 -m pip install requests
else
  echo "    'requests' is already present, skipping installation."
fi

step "Creating the cron job"
cat > "${CRON_FILE}" <<EOF
${CRON_SCHEDULE} root /usr/bin/python3 ${POLLER_SCRIPT} >> ${LOG_DIR}/poller.log 2>&1
EOF
chmod 644 "${CRON_FILE}"
echo "    ${CRON_FILE} (runs every 5 minutes as root)"

step "Restoring SELinux contexts (if applicable)"
if command -v getenforce &>/dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
  echo "    SELinux detected ($(getenforce)) - restoring contexts"
  restorecon -Rv /etc/cron.d/ "${CONFIG_DIR}" "${LOG_DIR}" "${SCRIPT_DIR}" 2>/dev/null || true
else
  echo "    SELinux not enforcing here, nothing to do."
fi

step "Adding the <localfile> entry to ossec.conf"
cp -p "${OSSEC_CONF}" "${OSSEC_BACKUP}"
if grep -q "${LOCALFILE_MARKER}" "${OSSEC_CONF}"; then
  echo "    Already present, skipping insert."
else
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
  echo "    Inserted."
fi

step "Adding detection rules to local_rules.xml"
touch "${LOCAL_RULES}"
cp -p "${LOCAL_RULES}" "${RULES_BACKUP}"
if grep -q "${RULES_MARKER}" "${LOCAL_RULES}"; then
  echo "    Already present, skipping insert."
else
  echo "    Checking for rule ID collisions (100250-100286)..."
  CONFLICTS=$(grep -rhoE "${RULES_ID_PATTERN}" /var/ossec/ruleset/rules/*.xml /var/ossec/etc/rules/*.xml 2>/dev/null | sort -u || true)
  if [[ -n "${CONFLICTS}" ]]; then
    echo "One or more rule IDs in the 100250-100286 range are already in use:" >&2
    echo "${CONFLICTS}" >&2
    echo "Aborting without changing local_rules.xml. Resolve the conflict and re-run." >&2
    exit 1
  fi
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
    <field name="type" type="pcre2">^(1108|1110|1111|1113|1117|1118)$</field>
    <description>Bitwarden: sensitive field viewed or copied - password/security code (itemId: $(itemId), actingUserId: $(actingUserId))</description>
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

</group>
<!-- END bitwarden-wazuh-rules -->
RULES_EOF
  echo "    Inserted 37 rules (IDs 100250-100286)."
fi

step "Validating the Wazuh configuration"
VALIDATION_FAILED=0
/var/ossec/bin/wazuh-logcollector -t || VALIDATION_FAILED=1
/var/ossec/bin/wazuh-analysisd -t || VALIDATION_FAILED=1

if [[ "${VALIDATION_FAILED}" -eq 1 ]]; then
  echo "Configuration test failed! Restoring both backups." >&2
  cp -p "${OSSEC_BACKUP}" "${OSSEC_CONF}"
  cp -p "${RULES_BACKUP}" "${LOCAL_RULES}"
  exit 1
fi
echo "    OK."

step "Restarting wazuh-manager"
systemctl restart wazuh-manager
sleep 3
echo "    Done."

cat <<EOF

==============================================================================
Deployment complete.

*** NEXT STEP - REQUIRED ***
Edit ${ORGS_CONFIG} with your real Bitwarden organization
credentials (see ${README_FILE} for how to obtain them),
then run once manually to pick them up immediately:

  sudo python3 ${POLLER_SCRIPT}

Without this step, the poller has nothing valid to authenticate with.

Verification:
  sudo tail -f ${LOG_DIR}/poller.log
  sudo tail -f /var/ossec/logs/alerts/alerts.json | grep '"description":"Bitwarden: '

Backups made this run (only needed if something looks wrong):
  ${OSSEC_BACKUP}
  ${RULES_BACKUP}

Full documentation: ${README_FILE}
==============================================================================
EOF

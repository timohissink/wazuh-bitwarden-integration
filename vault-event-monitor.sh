#!/usr/bin/env bash
# ==============================================================================
# Vault Event Monitor: Bitwarden -> Wazuh integration
# ==============================================================================
# One script that guides you through setting up (and later managing) a
# Bitwarden-to-Wazuh event pipeline: a Python poller, one or more
# Bitwarden organizations, a Wazuh <localfile> entry, and 45 detection
# rules.
#
# This script expects two sibling files in the same directory as itself
# (i.e. clone/download the whole repository, don't copy this file alone):
#   - bitwarden_wazuh_poller.py   the actual poller source code
#   - bitwarden-wazuh-rules.xml   the actual Wazuh detection rules
# Both are reviewable, testable, and version-controlled on their own -
# this script only copies them into place, it does not generate their
# content.
#
# Interactive use (recommended for first-time setup):
#   sudo bash vault-event-monitor.sh
#     -> shows a menu: Install / Add organization / Remove organization /
#        Status / Run the poller now / Update rules & configuration /
#        Uninstall / Exit
#
# Non-interactive use (for automation/CI/repeated testing):
#   sudo bash vault-event-monitor.sh install [--name NAME --client-id ID --client-secret SECRET] [--rules-mode managed|custom]
#   sudo bash vault-event-monitor.sh add-org --name NAME --client-id ID --client-secret SECRET [--identity-url URL] [--api-url URL]
#   sudo bash vault-event-monitor.sh remove-org --name NAME
#   sudo bash vault-event-monitor.sh status
#   sudo bash vault-event-monitor.sh run-now
#   sudo bash vault-event-monitor.sh update [--rules-mode managed|custom]
#   sudo bash vault-event-monitor.sh uninstall [--force]
#   sudo bash vault-event-monitor.sh help
#
# Rules modes:
#   managed (default) - the deployed rules file is refreshed from this
#                        repository's bitwarden-wazuh-rules.xml every time
#                        you run "update". Simple, but any hand-edits you
#                        make on the server to the deployed rules file
#                        will be overwritten on the next update.
#   custom             - the rules file is deployed once, then never
#                        touched again by "update". Edit
#                        /var/ossec/etc/rules/bitwarden-wazuh-rules.xml
#                        directly on the server; "update" will just tell
#                        you if the shipped version has changed since,
#                        so you can review and merge changes yourself.
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

# --- Where this script itself lives, so we can find its sibling files --------
SCRIPT_SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLLER_SOURCE="${SCRIPT_SOURCE_DIR}/bitwarden_wazuh_poller.py"
RULES_SOURCE="${SCRIPT_SOURCE_DIR}/bitwarden-wazuh-rules.xml"

# --- Paths on the target (Wazuh manager) system -------------------------------
SCRIPT_DIR="/opt/scripts"
POLLER_SCRIPT="${SCRIPT_DIR}/bitwarden_wazuh_poller.py"

CONFIG_DIR="/etc/bitwarden-wazuh"
ORGS_CONFIG="${CONFIG_DIR}/organizations.json"
ORGS_EXAMPLE="${CONFIG_DIR}/organizations.json.example"
README_FILE="${CONFIG_DIR}/README.md"
RULES_MODE_FILE="${CONFIG_DIR}/.rules_mode"

LOG_DIR="/var/log/bitwarden"
CRON_FILE="/etc/cron.d/bitwarden-wazuh"
# Every minute: close to the practical floor. Bitwarden's own clients
# batch-upload events to Bitwarden's server only every ~60 seconds (see
# bitwarden.com/help/event-logs), so even instant polling on our side
# can't make an event visible sooner than that.
CRON_SCHEDULE="* * * * *"

OSSEC_CONF="/var/ossec/etc/ossec.conf"
RULES_DIR="/var/ossec/etc/rules"
DEPLOYED_RULES_FILE="${RULES_DIR}/bitwarden-wazuh-rules.xml"

WAZUH_GROUP="wazuh"   # standard service account group created by every Wazuh install

LOCALFILE_BEGIN="<!-- BEGIN bitwarden-wazuh-localfile -->"
LOCALFILE_END="<!-- END bitwarden-wazuh-localfile -->"
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

require_sibling_files() {
  local missing=0
  if [[ ! -f "${POLLER_SOURCE}" ]]; then
    echo "Cannot find ${POLLER_SOURCE}" >&2
    missing=1
  fi
  if [[ ! -f "${RULES_SOURCE}" ]]; then
    echo "Cannot find ${RULES_SOURCE}" >&2
    missing=1
  fi
  if [[ "${missing}" -eq 1 ]]; then
    echo "This script expects bitwarden_wazuh_poller.py and bitwarden-wazuh-rules.xml" >&2
    echo "in the same directory as itself - clone/download the full repository," >&2
    echo "don't copy this .sh file on its own." >&2
    return 1
  fi
  return 0
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

get_rules_mode() {
  if [[ -f "${RULES_MODE_FILE}" ]]; then
    cat "${RULES_MODE_FILE}"
  else
    echo "managed"
  fi
}

# Interactively asks how rules should be managed. Prints "managed" or
# "custom" to stdout (capture with $(...)).
prompt_rules_mode() {
  echo "How should the Wazuh detection rules be managed?" >&2
  echo "  1) Automatically keep them in sync with this repo (recommended)" >&2
  echo "  2) Deploy once, then I will manage/customize them myself" >&2
  echo "     (rule IDs, levels, groups, descriptions - your changes are kept)" >&2
  local choice
  read -r -p "Choose [1]: " choice
  if [[ "${choice}" == "2" ]]; then
    echo "custom"
  else
    echo "managed"
  fi
}
# ==============================================================================
# Infrastructure functions
# ==============================================================================

ensure_directories() {
  mkdir -p "${SCRIPT_DIR}" "${CONFIG_DIR}" "${LOG_DIR}"
}

# Copies the real poller source file (bitwarden_wazuh_poller.py, living
# next to this script) into place. The poller is NOT generated/embedded -
# this just deploys the actual, reviewable file from the repository.
write_poller_script() {
  if [[ ! -f "${POLLER_SOURCE}" ]]; then
    echo "Cannot find ${POLLER_SOURCE} - see the note at the top of this script." >&2
    return 1
  fi
  cp "${POLLER_SOURCE}" "${POLLER_SCRIPT}"
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
# Bitwarden -> Wazuh integration (Vault Event Monitor)

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

## Wazuh detection rules

The rules live in their own file, `/var/ossec/etc/rules/bitwarden-wazuh-rules.xml`
(sourced from `bitwarden-wazuh-rules.xml` in the repository, not embedded
in any script) - review, diff, or hand-edit it like any other Wazuh rules
file.

Two management modes, chosen during install (or overridden with
`--rules-mode` on `install`/`update`):

- **managed** (default): `update` refreshes the deployed rules file from
  the repository every time.
- **custom**: `update` never touches the deployed rules file again once
  it's been deployed once. If the shipped version has changed since,
  `update` just tells you so, so you can review and merge by hand.

Check the current mode:

```bash
cat /etc/bitwarden-wazuh/.rules_mode
```

## What this integration created

| Path | Purpose |
|---|---|
| `/opt/scripts/bitwarden_wazuh_poller.py` | The poller itself |
| `/etc/bitwarden-wazuh/organizations.json` | Your real credentials (secret) |
| `/etc/bitwarden-wazuh/organizations.json.example` | Documented template |
| `/etc/bitwarden-wazuh/.rules_mode` | Whether rules are "managed" or "custom" |
| `/var/log/bitwarden/events.log` | Collected events (monitored by Wazuh) |
| `/var/log/bitwarden/poller.log` | Poller's own run log (cron output) |
| `/etc/cron.d/bitwarden-wazuh` | Schedules the poller every minute |
| `/var/ossec/etc/ossec.conf` | `<localfile>` block added (marked) |
| `/var/ossec/etc/rules/bitwarden-wazuh-rules.xml` | 45 detection rules, its own dedicated file |

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
    restorecon -Rv /etc/cron.d/ "${CONFIG_DIR}" "${LOG_DIR}" "${SCRIPT_DIR}" "${RULES_DIR}" 2>/dev/null || true
  fi
}
# ==============================================================================
# Wazuh configuration functions
# ==============================================================================
# Two independent pieces:
#   1. The <localfile> entry in ossec.conf - still a small marker-wrapped
#      block inserted/removed in place, since ossec.conf is a single
#      monolithic file with no directory-based auto-include for this.
#   2. The detection rules - now a fully separate, dedicated file
#      (bitwarden-wazuh-rules.xml) dropped into Wazuh's rules directory,
#      which Wazuh auto-loads like any other rules file. No more
#      surgical insert/remove into a shared file, and no more embedded
#      rule content in this script - see deploy_rules_file() below.

# Removes a marker-delimited block from a file in place, if both markers
# are present. Leaves the file untouched otherwise. Safe to call on a
# file that doesn't contain the block at all. (Only used for ossec.conf's
# <localfile> entry now - the rules are a standalone file, not a block
# inside a shared one.)
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

# Checks for rule ID collisions against every OTHER rule file Wazuh loads
# (excluding our own dedicated rules file, so re-deploying doesn't
# collide with itself on every run).
check_rules_id_collisions() {
  local files=() f
  for f in /var/ossec/ruleset/rules/*.xml "${RULES_DIR}"/*.xml; do
    [[ -f "${f}" ]] || continue
    [[ "${f}" == "${DEPLOYED_RULES_FILE}" ]] && continue
    files+=("${f}")
  done

  [[ ${#files[@]} -eq 0 ]] && return 0

  local conflicts
  conflicts=$(grep -hoE "${RULES_ID_PATTERN}" "${files[@]}" 2>/dev/null | sort -u || true)
  if [[ -n "${conflicts}" ]]; then
    echo "One or more rule IDs in the 100250-100294 range are already in use:" >&2
    echo "${conflicts}" >&2
    return 1
  fi
  return 0
}

# deploy_rules_file MODE   (MODE: "managed" or "custom")
#
# managed: always (re)copies bitwarden-wazuh-rules.xml from the repo over
#          the deployed file.
# custom:  copies it once if not already deployed; if it's already
#          deployed, leaves it completely untouched (that's the whole
#          point of "custom" mode) and just notes if the shipped version
#          has since changed, so you can review/merge by hand.
deploy_rules_file() {
  local mode="$1"

  if [[ "${mode}" != "managed" && "${mode}" != "custom" ]]; then
    echo "Invalid rules mode '${mode}' (expected 'managed' or 'custom')." >&2
    return 1
  fi

  if [[ "${mode}" == "custom" && -f "${DEPLOYED_RULES_FILE}" ]]; then
    echo "custom" > "${RULES_MODE_FILE}"
    if ! diff -q "${DEPLOYED_RULES_FILE}" "${RULES_SOURCE}" &>/dev/null; then
      echo "Rules mode: custom - your deployed rules file was left untouched."
      echo "Note: the version in this repository has changed since. Review with:"
      echo "  diff ${DEPLOYED_RULES_FILE} ${RULES_SOURCE}"
    else
      echo "Rules mode: custom - your deployed rules file was left untouched (matches the repo anyway)."
    fi
    return 0
  fi

  cp "${RULES_SOURCE}" "${DEPLOYED_RULES_FILE}"
  chmod 644 "${DEPLOYED_RULES_FILE}"
  echo "${mode}" > "${RULES_MODE_FILE}"
  echo "Rules mode: ${mode} - deployed $(grep -c '<rule id=' "${DEPLOYED_RULES_FILE}") rules to ${DEPLOYED_RULES_FILE}."
}

# Refreshes both the localfile entry and the rules file (used by both
# install and update): backs up, checks for ID collisions, deploys fresh,
# validates, and restarts - rolling back both on failure.
# refresh_wazuh_config RULES_MODE
refresh_wazuh_config() {
  local rules_mode="$1"
  local ts ossec_backup rules_backup=""

  ts="$(date +%Y%m%d%H%M%S)"
  ossec_backup="${OSSEC_CONF}.bak.${ts}"
  cp -p "${OSSEC_CONF}" "${ossec_backup}"

  if [[ -f "${DEPLOYED_RULES_FILE}" ]]; then
    rules_backup="${DEPLOYED_RULES_FILE}.bak.${ts}"
    cp -p "${DEPLOYED_RULES_FILE}" "${rules_backup}"
  fi

  remove_marked_block "${OSSEC_CONF}" "${LOCALFILE_BEGIN}" "${LOCALFILE_END}"

  if ! check_rules_id_collisions; then
    echo "Aborting without changing anything further. Resolve the conflict and re-run." >&2
    cp -p "${ossec_backup}" "${OSSEC_CONF}"
    return 1
  fi

  insert_localfile_block

  if ! deploy_rules_file "${rules_mode}"; then
    echo "Restoring ossec.conf backup due to the rules deployment error above." >&2
    cp -p "${ossec_backup}" "${OSSEC_CONF}"
    return 1
  fi

  if ! /var/ossec/bin/wazuh-logcollector -t || ! /var/ossec/bin/wazuh-analysisd -t; then
    echo "Configuration test failed! Restoring backups." >&2
    cp -p "${ossec_backup}" "${OSSEC_CONF}"
    [[ -n "${rules_backup}" ]] && cp -p "${rules_backup}" "${DEPLOYED_RULES_FILE}"
    return 1
  fi

  systemctl restart wazuh-manager
  sleep 3
  echo "Backup (only needed if something looks wrong): ${ossec_backup}"
  [[ -n "${rules_backup}" ]] && echo "Rules backup: ${rules_backup}"
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

# do_install [NAME] [CLIENT_ID] [CLIENT_SECRET] [IDENTITY_URL] [API_URL] [RULES_MODE]
do_install() {
  local name="${1:-}" client_id="${2:-}" client_secret="${3:-}" identity_url="${4:-}" api_url="${5:-}" rules_mode_arg="${6:-}"
  local org_configured=0

  require_sibling_files || return 1

  echo "=== Installing Vault Event Monitor (Bitwarden -> Wazuh) ==="
  echo
  echo "Setting up files and permissions..."
  ensure_directories
  write_poller_script || return 1
  ensure_config_scaffolding
  set_permissions
  ensure_python_deps
  write_cron_job
  selinux_restore

  local rules_mode
  if [[ -n "${rules_mode_arg}" ]]; then
    rules_mode="${rules_mode_arg}"
  elif is_tty; then
    rules_mode="$(prompt_rules_mode)"
  else
    rules_mode="managed"
  fi

  echo "Setting up the Wazuh <localfile> entry and detection rules..."
  if ! refresh_wazuh_config "${rules_mode}"; then
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

# do_update [RULES_MODE]   (defaults to whatever was chosen at install time)
do_update() {
  require_installed || return 1
  require_sibling_files || return 1

  local rules_mode="${1:-}"
  if [[ -z "${rules_mode}" ]]; then
    rules_mode="$(get_rules_mode)"
  fi

  echo "=== Updating poller script and Wazuh configuration (rules mode: ${rules_mode}) ==="
  echo "(organizations.json is never touched by this)"
  echo
  write_poller_script || return 1
  ensure_config_scaffolding
  set_permissions
  ensure_python_deps
  write_cron_job
  selinux_restore

  if ! refresh_wazuh_config "${rules_mode}"; then
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
  echo "=== Vault Event Monitor Status (Bitwarden -> Wazuh) ==="
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

  if [[ -f "${DEPLOYED_RULES_FILE}" ]]; then
    local count mode
    count=$(grep -cE "${RULES_ID_PATTERN}" "${DEPLOYED_RULES_FILE}" 2>/dev/null || echo 0)
    mode="$(get_rules_mode)"
    echo "Wazuh rules:      installed (${count} rules, mode: ${mode}, ${DEPLOYED_RULES_FILE})"
    if [[ "${mode}" == "custom" && -f "${RULES_SOURCE}" ]] && ! diff -q "${DEPLOYED_RULES_FILE}" "${RULES_SOURCE}" &>/dev/null; then
      echo "                  (note: differs from the version in this repo - see README)"
    fi
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
  - ${DEPLOYED_RULES_FILE} (the 45 detection rules - including any of your own
    customizations, if you were running in "custom" rules mode)

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

  echo "Removing the detection rules file..."
  rm -f "${DEPLOYED_RULES_FILE}"

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
    echo "=== Vault Event Monitor: Bitwarden -> Wazuh Integration ==="
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
  ARG_NAME="" ARG_CLIENT_ID="" ARG_CLIENT_SECRET="" ARG_IDENTITY_URL="" ARG_API_URL="" ARG_RULES_MODE=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --name) ARG_NAME="${2:-}"; shift 2 ;;
      --client-id) ARG_CLIENT_ID="${2:-}"; shift 2 ;;
      --client-secret) ARG_CLIENT_SECRET="${2:-}"; shift 2 ;;
      --identity-url) ARG_IDENTITY_URL="${2:-}"; shift 2 ;;
      --api-url) ARG_API_URL="${2:-}"; shift 2 ;;
      --rules-mode) ARG_RULES_MODE="${2:-}"; shift 2 ;;
      *) echo "Unknown option: $1" >&2; return 1 ;;
    esac
  done
  if [[ -n "${ARG_RULES_MODE}" && "${ARG_RULES_MODE}" != "managed" && "${ARG_RULES_MODE}" != "custom" ]]; then
    echo "--rules-mode must be 'managed' or 'custom'." >&2
    return 1
  fi
  return 0
}

cmd_install() {
  if ! parse_org_flags "$@"; then
    print_help
    exit 1
  fi
  do_install "${ARG_NAME}" "${ARG_CLIENT_ID}" "${ARG_CLIENT_SECRET}" "${ARG_IDENTITY_URL}" "${ARG_API_URL}" "${ARG_RULES_MODE}"
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

cmd_update() {
  if ! parse_org_flags "$@"; then
    print_help
    exit 1
  fi
  do_update "${ARG_RULES_MODE}"
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
Vault Event Monitor - Bitwarden -> Wazuh integration

Interactive use (recommended for first-time setup):
  sudo bash vault-event-monitor.sh

Non-interactive use:
  sudo bash vault-event-monitor.sh install [--name NAME --client-id ID --client-secret SECRET [--identity-url URL] [--api-url URL]] [--rules-mode managed|custom]
  sudo bash vault-event-monitor.sh add-org --name NAME --client-id ID --client-secret SECRET [--identity-url URL] [--api-url URL]
  sudo bash vault-event-monitor.sh remove-org --name NAME
  sudo bash vault-event-monitor.sh status
  sudo bash vault-event-monitor.sh run-now
  sudo bash vault-event-monitor.sh update [--rules-mode managed|custom]
  sudo bash vault-event-monitor.sh uninstall [--force]
  sudo bash vault-event-monitor.sh help

Rules modes:
  managed (default) - "update" always refreshes the deployed rules file
                       from bitwarden-wazuh-rules.xml in this repository.
  custom             - the rules file is deployed once, then never
                       touched again by "update" - edit it directly on
                       the server and it's yours to keep.

Examples:
  sudo bash vault-event-monitor.sh install --name "Acme Corp" --client-id "organization.xxxx" --client-secret "xxxx" --rules-mode custom
  sudo bash vault-event-monitor.sh add-org --name "Acme NL" --client-id "organization.yyyy" --client-secret "yyyy"
  sudo bash vault-event-monitor.sh remove-org --name "Acme NL"
  sudo bash vault-event-monitor.sh update --rules-mode managed
  sudo bash vault-event-monitor.sh uninstall --force

This script expects two sibling files next to it (from the same
repository): bitwarden_wazuh_poller.py and bitwarden-wazuh-rules.xml
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
    update) cmd_update "$@" ;;
    uninstall) cmd_uninstall "$@" ;;
    *)
      echo "Unknown command: ${command}" >&2
      print_help
      exit 1
      ;;
  esac
}

main "$@"

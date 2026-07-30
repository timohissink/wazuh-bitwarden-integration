#!/usr/bin/env bash
# ==============================================================================
# Bitwarden -> Wazuh integration: cleanup script
# ==============================================================================
# Removes everything deploy-bitwarden-wazuh.sh created, so the deployment
# can be tested again from a clean state. This includes real secrets
# (organizations.json) and reverts production Wazuh configuration files,
# so it asks for confirmation before doing anything destructive.
#
# NOT removed: the Python 'requests' module - assumed pre-existing.
#
# Usage:
#   sudo bash cleanup-bitwarden-wazuh.sh          # asks for confirmation
#   sudo bash cleanup-bitwarden-wazuh.sh --force  # skips confirmation (for
#                                                  # scripted/repeated testing)
# ==============================================================================

set -uo pipefail  # no -e: we want to keep going even if something's already gone

SCRIPT_DIR="/opt/scripts"
POLLER_SCRIPT="${SCRIPT_DIR}/bitwarden_wazuh_poller.py"

CONFIG_DIR="/etc/bitwarden-wazuh"

LOG_DIR="/var/log/bitwarden"
CRON_FILE="/etc/cron.d/bitwarden-wazuh"

OSSEC_CONF="/var/ossec/etc/ossec.conf"
LOCAL_RULES="/var/ossec/etc/rules/local_rules.xml"

LOCALFILE_BEGIN="<!-- BEGIN bitwarden-wazuh-localfile -->"
LOCALFILE_END="<!-- END bitwarden-wazuh-localfile -->"
RULES_BEGIN="<!-- BEGIN bitwarden-wazuh-rules -->"
RULES_END="<!-- END bitwarden-wazuh-rules -->"

FORCE=0
for arg in "$@"; do
  if [[ "${arg}" == "--force" || "${arg}" == "-f" ]]; then
    FORCE=1
  fi
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script must be run as root (or via sudo)." >&2
  exit 1
fi

# Remove a marker-delimited block from a file in place, if both markers
# are present. Leaves the file untouched otherwise.
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

# Also eat one adjacent blank line, if present, to avoid leaving a gap.
new_content = content[:start].rstrip() + "\n" + content[end:].lstrip("\n")

with open(path, "w") as f:
    f.write(new_content)
PYEOF
    return 0
  fi
  return 1
}

if [[ "${FORCE}" -eq 0 ]]; then
  cat <<EOF
This will permanently remove:
  - ${POLLER_SCRIPT}
  - ${CONFIG_DIR}/  (including organizations.json - YOUR REAL BITWARDEN SECRETS)
  - ${LOG_DIR}/     (collected events, state, caches)
  - ${CRON_FILE}
  - The <localfile> block in ${OSSEC_CONF}
  - The 37 detection rules (IDs 100250-100286) in ${LOCAL_RULES}

The Wazuh manager will be restarted afterwards.
Not removed: the Python 'requests' module.

EOF
  read -r -p "Type 'DELETE' to confirm: " CONFIRMATION
  if [[ "${CONFIRMATION}" != "DELETE" ]]; then
    echo "Aborted, nothing was changed."
    exit 1
  fi
fi

echo
echo "==> Removing cron job: ${CRON_FILE}"
rm -f "${CRON_FILE}"

echo "==> Removing poller script: ${POLLER_SCRIPT}"
rm -f "${POLLER_SCRIPT}"
rmdir --ignore-fail-on-non-empty "${SCRIPT_DIR}" 2>/dev/null || true

echo "==> Removing config directory: ${CONFIG_DIR} (including organizations.json)"
rm -rf "${CONFIG_DIR}"

echo "==> Removing log/state directory: ${LOG_DIR}"
rm -rf "${LOG_DIR}"

echo "==> Reverting ${OSSEC_CONF}"
if remove_marked_block "${OSSEC_CONF}" "${LOCALFILE_BEGIN}" "${LOCALFILE_END}"; then
  echo "    <localfile> block removed."
else
  echo "    Nothing to remove (block not present)."
fi

echo "==> Reverting ${LOCAL_RULES}"
if remove_marked_block "${LOCAL_RULES}" "${RULES_BEGIN}" "${RULES_END}"; then
  echo "    Rules block removed."
else
  echo "    Nothing to remove (block not present)."
fi

echo "==> Validating the reverted Wazuh configuration"
VALIDATION_FAILED=0
if [[ -x /var/ossec/bin/wazuh-logcollector ]]; then
  /var/ossec/bin/wazuh-logcollector -t || VALIDATION_FAILED=1
fi
if [[ -x /var/ossec/bin/wazuh-analysisd ]]; then
  /var/ossec/bin/wazuh-analysisd -t || VALIDATION_FAILED=1
fi
if [[ "${VALIDATION_FAILED}" -eq 1 ]]; then
  echo "    Warning: validation reported problems - please check ${OSSEC_CONF} and ${LOCAL_RULES} manually." >&2
else
  echo "    OK."
fi

if command -v systemctl &>/dev/null && systemctl list-unit-files 2>/dev/null | grep -q wazuh-manager; then
  echo "==> Restarting wazuh-manager"
  systemctl restart wazuh-manager
  sleep 3
  echo "    Done."
fi

cat <<EOF

==============================================================================
Cleanup complete.

Deliberately not removed:
  - The Python 'requests' module
  - Any pre-existing content of ${OSSEC_CONF} / ${LOCAL_RULES} outside the
    marked blocks

You can now re-run:
  sudo bash deploy-bitwarden-wazuh.sh
==============================================================================
EOF

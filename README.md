# Bitwarden → Wazuh Integration

Feed Bitwarden organization event logs into an existing Wazuh manager as
proper, correctly-classified alerts — logins, failed-login/brute-force
detection, vault exports, mass deletions, organization/policy changes,
and Bitwarden Send activity — enriched with member email addresses
instead of raw GUIDs, across one or more Bitwarden organizations.

```
Bitwarden Public API (1..N organizations)
        │
        ▼
  Python poller (cron, every 5 min)
   - resolves actingUserId / memberId → email
   - tags each event with its organization
        │
        ▼
  /var/log/bitwarden/events.log
        │
        ▼
  Wazuh <localfile> (JSON)
        │
        ▼
  37 custom detection rules
        │
        ▼
  Wazuh alerts
```

## Features

- **Multi-organization**: monitor any number of Bitwarden organizations
  (cloud and/or self-hosted) from a single deployment. One organization
  failing (e.g. a revoked key) never blocks the others.
- **Member email enrichment**: `actingUserId` / `memberId` GUIDs are
  resolved to real email addresses via Bitwarden's `/public/members`
  endpoint, with local caching and graceful fallback if that endpoint is
  temporarily unavailable. The original GUID is always preserved
  alongside the resolved value.
- **37 built-in detection rules**, including brute-force and mass-deletion
  frequency correlation — see [Detection rules](#detection-rules) below.
- **Idempotent**: safe to re-run the deploy script at any time; it never
  overwrites your real credentials, and never duplicates config it has
  already added.
- **Self-contained**: `deploy-bitwarden-wazuh.sh` is the *only* file you
  need on the target server — the poller script, config templates, and
  Wazuh rules are all embedded inside it and written out during setup.

### A note on what this can't do

Bitwarden item **names** (e.g. "Amazon Account ICT") can never appear in
alerts — Bitwarden encrypts item names client-side as part of its
zero-knowledge architecture, so the server (and therefore any API) never
has access to plaintext item names. Only the item's opaque `itemId` GUID
is available. Member/user identities are different: emails are stored
server-side for account management, which is why those *can* be resolved.

## Requirements

- An existing, working Wazuh **manager** (this does not install Wazuh)
- Root/sudo access on that manager
- Outbound HTTPS access to Bitwarden's API (or your self-hosted instance)
- At least one Bitwarden organization on a **Teams or Enterprise** plan,
  with access to generate an organization API key

## Quick start

```bash
git clone <this-repo>
cd <this-repo>
chmod +x deploy-bitwarden-wazuh.sh
sudo bash deploy-bitwarden-wazuh.sh
```

Then edit the credentials file it created, and run the poller once to
pick them up immediately:

```bash
sudo nano /etc/bitwarden-wazuh/organizations.json
sudo python3 /opt/scripts/bitwarden_wazuh_poller.py
```

## Configuration

Organizations are defined in `/etc/bitwarden-wazuh/organizations.json` —
a JSON array, one object per organization:

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
2. Open the Admin Console → **Settings** → **Organization info** →
   **API Key**, and view (or rotate) the key.
3. Copy the `client_id` (starts with `organization.`) and the
   `client_secret` into an entry in `organizations.json`.

### Adding more organizations

Add another object to the array — each is polled and processed
independently:

```json
[
  { "name": "Acme Corp", "client_id": "...", "client_secret": "..." },
  { "name": "Acme NL",   "client_id": "...", "client_secret": "..." }
]
```

### Self-hosted Bitwarden

Add `identity_url` and `api_url` to that organization's entry (leave them
out for Bitwarden Cloud, which is the default):

```json
{
  "name": "Acme Self-Hosted",
  "client_id": "organization.yyyy...",
  "client_secret": "yyyy...",
  "identity_url": "https://bitwarden.acme.example.com/identity/connect/token",
  "api_url": "https://bitwarden.acme.example.com/api/public"
}
```

### Documenting the file without breaking it

Plain JSON has no comment syntax. An entry with only a `_comment` key is
always ignored, so you can leave usage notes inside the file itself:

```json
{ "_comment": "Add another organization here, like the one above." }
```

### Applying changes

Changes take effect on the next scheduled run (every 5 minutes, via
cron), or immediately:

```bash
sudo python3 /opt/scripts/bitwarden_wazuh_poller.py
```

## What gets installed

| Path | Purpose |
|---|---|
| `/opt/scripts/bitwarden_wazuh_poller.py` | The poller itself |
| `/etc/bitwarden-wazuh/organizations.json` | Your real credentials (secret, `600`, never overwritten on re-deploy) |
| `/etc/bitwarden-wazuh/organizations.json.example` | Documented template |
| `/etc/bitwarden-wazuh/README.md` | Copy of the configuration docs, on the server itself |
| `/var/log/bitwarden/events.log` | Collected events (monitored by Wazuh) |
| `/var/log/bitwarden/poller.log` | Poller's own run log (cron output) |
| `/etc/cron.d/bitwarden-wazuh` | Runs the poller every 5 minutes, as root |
| `/var/ossec/etc/ossec.conf` | `<localfile>` block added (wrapped in marker comments) |
| `/var/ossec/etc/rules/local_rules.xml` | 37 detection rules added, IDs `100250`–`100286` (wrapped in marker comments) |

Both Wazuh config changes are wrapped in
`<!-- BEGIN/END bitwarden-wazuh-... -->` marker comments, so they can be
found and cleanly removed (see [Uninstalling](#uninstalling)) without
touching the rest of your configuration. A timestamped backup of both
files is also made before every change.

## Detection rules

| Category | Example IDs | Level | Notes |
|---|---|---|---|
| Authentication | 100251–100253 | 3–5 | Login, failed login |
| **Brute-force detection** | 100254 | **10** | 5 failed logins / 2 min, same user (frequency rule) |
| Account security changes | 100255–100259 | 3–8 | Password change, 2FA on/off, account recovery |
| **Vault export / purge** | 100260–100262 | **12–15** | Individual/org export, org vault purge |
| Item events | 100263–100266, 100268 | 3–8 | Create/edit/delete, sensitive field access |
| **Mass deletion detection** | 100267 | **12** | 10+ deletions / 5 min, same user (frequency rule) |
| Organization membership | 100269–100273 | 5–8 | Invited, removed, access revoked/restored |
| **Organization/security settings** | 100274–100279 | 8–10 | Org settings, **SSO/Key Connector disabled**, policy changes |
| Claimed domains | 100280 | 5 | |
| Secrets Manager | 100281–100283 | 5–8 | Secret/project/machine account deleted |
| Bitwarden Send | 100284–100286 | 3 | Created/deleted/accessed |

Full rule definitions (field matches, descriptions, MITRE mapping for the
brute-force rule) are in the script itself — see the rules block inside
`deploy-bitwarden-wazuh.sh`, or `/var/ossec/etc/rules/local_rules.xml`
after deployment.

## Verifying it works

```bash
sudo tail -f /var/log/bitwarden/poller.log
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep '"description":"Bitwarden: '
```

Or test a specific collected event directly against the rules:

```bash
sudo tail -1 /var/log/bitwarden/events.log \
  | sudo /var/ossec/bin/wazuh-logtest 2>&1 | sed -n '/Phase 3/,$p'
```

## Uninstalling

```bash
sudo bash cleanup-bitwarden-wazuh.sh          # asks for confirmation
sudo bash cleanup-bitwarden-wazuh.sh --force  # skips it (for scripted use)
```

This removes everything the deploy script created — including
`organizations.json` and its real secrets — and cleanly reverts
`ossec.conf` / `local_rules.xml` using the marker comments, leaving any
unrelated configuration untouched. The Python `requests` module is never
removed, since it's assumed to be a pre-existing system dependency.

## Repository structure

| File | Purpose |
|---|---|
| `deploy-bitwarden-wazuh.sh` | The only file needed to deploy the full integration |
| `cleanup-bitwarden-wazuh.sh` | Fully reverses a deployment |

## Security notes

- `organizations.json` contains plaintext API secrets. It is created
  with `600` permissions, owned by `root`. **Never commit a filled-in
  copy to version control** — only `organizations.json.example` (which
  ships with placeholder values) is meant to be shared.
- Rotate a Bitwarden organization API key immediately if you ever
  suspect it has been exposed (e.g. pasted somewhere insecure) — this is
  done from the same Admin Console page used to view it.
- `/var/log/bitwarden` is `root:wazuh`, mode `2750` (setgid), so the
  Wazuh service account can read collected events without the directory
  being world-readable.

## License

Choose and add a license file appropriate for your use case (e.g. MIT,
Apache-2.0) — none is included by default.

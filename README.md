# Bitwarden to Wazuh SIEM Integration

> Turn Bitwarden organisation events into clear, actionable Wazuh alerts — without building and maintaining your own API poller or detection rules.

![Bash](https://img.shields.io/badge/Bash-5.0%2B-4EAA25?logo=gnubash&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.7%2B-3776AB?logo=python&logoColor=white)
![Wazuh](https://img.shields.io/badge/Wazuh-4.x-1E90FF)
![Bitwarden](https://img.shields.io/badge/Bitwarden-Cloud%20%7C%20self--hosted-175DDC)

Bitwarden gives you the audit trail. Wazuh gives you the visibility. This project connects the two, enriching Bitwarden organisation events and classifying them with **45 ready-to-use Wazuh detection rules**.

Instead of a stream of opaque event codes and GUIDs, your team gets alerts that say what happened, who did it, and how urgently to investigate.

```text
Bitwarden organisation events → enriched JSON → Wazuh rules → actionable alerts
```

## Why use it?

- **Detect the events that matter.** Flag vault exports, organisation-vault purges, mass deletions, risky security-setting changes, and more.
- **Spot brute-force attempts.** Five failed logins from the same user within two minutes become a single correlated alert.
- **See people, not IDs.** Where Bitwarden makes the information available, user IDs are resolved to email addresses.
- **Start fast.** Run one script and follow the guided setup; no custom Wazuh rule design required.
- **Fit your environment.** Monitor one or many Bitwarden Cloud and self-hosted organisations from the same Wazuh manager.
- **Automate confidently.** Every menu action also has a non-interactive command for Ansible, CI, or other automation.

## What an alert looks like

Raw events are not much fun to investigate:

```json
{ "type": 1007, "actingUserId": "affe2391-9e7b-4c94-90fd-b3fe00ad5a25" }
```

This integration turns that into a high-signal Wazuh alert:

```json
{
  "rule": {
    "id": "100260",
    "level": 12,
    "description": "Bitwarden: user exported their individual vault items (actingUserId: jane@company.com)",
    "groups": ["bitwarden", "data_loss"]
  }
}
```

No hunting through numeric event types. No guessing whether a log line needs attention.

## Get started in minutes

### Before you begin

You need:

- a working **Wazuh manager** (this project does not install Wazuh);
- `sudo` or root access on that manager;
- outbound HTTPS access to Bitwarden or your self-hosted instance; and
- a Bitwarden organisation on a **Teams or Enterprise** plan, with an organisation API key.

### Install

```bash
git clone https://github.com/timohissink/wazuh-bitwarden-integration
cd wazuh-bitwarden-integration
chmod +x bitwarden-wazuh.sh
sudo bash bitwarden-wazuh.sh
```

Choose **Install integration** and enter your organisation name, client ID, and client secret. If you already have the API key, setup takes only a few minutes.

Need an API key? In the Bitwarden web vault, go to **Admin Console → Settings → Organisation info → API Key**. You must be an organisation Owner or Admin.

## How it works

```text
Bitwarden Public API (one or more organisations)
                  │
                  ▼
      Python poller, every minute
      • fetches new organisation events
      • resolves member/user IDs to emails
      • tags events with their organisation
                  │
                  ▼
    /var/log/bitwarden/events.log
                  │
                  ▼
       Wazuh JSON log monitoring
                  │
                  ▼
       45 Bitwarden detection rules
                  │
                  ▼
          Wazuh alerts
```

## Use the guided menu

```bash
sudo bash bitwarden-wazuh.sh
```

```text
1) Install integration (default)
2) Add an organisation
3) Remove an organisation
4) Show status
5) Run the poller now (test)
6) Update rules & configuration
7) Uninstall integration
8) Exit
```

Prompts have sensible defaults. After adding an organisation, you can run an immediate test instead of waiting for the next scheduled poll.

## Automate it

All actions are also available without the menu:

```bash
sudo bash bitwarden-wazuh.sh install --name "Acme Corp" --client-id "organization.xxxx" --client-secret "xxxx"
sudo bash bitwarden-wazuh.sh add-org --name "Acme NL" --client-id "organization.yyyy" --client-secret "yyyy"
sudo bash bitwarden-wazuh.sh remove-org --name "Acme NL"
sudo bash bitwarden-wazuh.sh status
sudo bash bitwarden-wazuh.sh run-now
sudo bash bitwarden-wazuh.sh update
sudo bash bitwarden-wazuh.sh uninstall --force
sudo bash bitwarden-wazuh.sh help
```

The script only prompts when attached to an interactive terminal, making it suitable for configuration management and CI.

## Self-hosted Bitwarden

Bitwarden Cloud is the default. For a self-hosted organisation, add your identity and API endpoints:

```bash
sudo bash bitwarden-wazuh.sh add-org \
  --name "Acme Self-Hosted" \
  --client-id "organization.yyyy" \
  --client-secret "yyyy" \
  --identity-url "https://bitwarden.acme.example.com/identity/connect/token" \
  --api-url "https://bitwarden.acme.example.com/api/public"
```

Cloud and self-hosted organisations can run side by side.

## What it detects

| Area | Rule IDs | Typical severity | Examples |
|---|---:|---:|---|
| Authentication | 100251–100254 | 3–10 | Logins, failed logins, brute-force detection |
| Account security | 100255–100259 | 3–8 | Password, 2FA, and recovery changes |
| Data loss | 100260–100262 | 12–15 | Vault export and organisation-vault purge |
| Vault items | 100263–100268 | 3–12 | Create, edit, delete, sensitive-field access, mass deletion |
| Organisation access | 100269–100273, 100291 | 5–8 | Invitations, removals, access changes |
| Security settings | 100274–100279, 100292 | 8–10 | SSO, Key Connector, and policy changes |
| Collections and groups | 100288–100289 | 3 | Collection and group activity |
| Secrets Manager | 100281–100283, 100293 | 3–8 | Secrets-related events |
| Bitwarden Send | 100284–100286, 100294 | 3 | Send activity |
| Other item/account activity | 100287, 100290 | 3 | Item views, autofill, and account events |

Every currently documented Bitwarden event type has a tailored rule. Events added by Bitwarden in the future fall back to the generic `100250` classifier until a dedicated mapping is added.

## Verify the integration

```bash
sudo bash bitwarden-wazuh.sh status
sudo tail -f /var/log/bitwarden/poller.log
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep '"description":"Bitwarden: '
```

To test the most recently collected event directly against Wazuh's rules:

```bash
sudo tail -1 /var/log/bitwarden/events.log \
  | sudo /var/ossec/bin/wazuh-logtest 2>&1 | sed -n '/Phase 3/,$p'
```

## What gets installed

| Path | Purpose |
|---|---|
| `/opt/scripts/bitwarden_wazuh_poller.py` | Polls the Bitwarden Public API |
| `/etc/bitwarden-wazuh/organizations.json` | Credentials and organisation settings (mode `600`) |
| `/etc/bitwarden-wazuh/organizations.json.example` | Shareable configuration template |
| `/etc/bitwarden-wazuh/README.md` | Configuration documentation on the server |
| `/var/log/bitwarden/events.log` | Events monitored by Wazuh |
| `/etc/cron.d/bitwarden-wazuh` | Runs the poller every minute |
| `/var/ossec/etc/ossec.conf` | Adds the Wazuh `<localfile>` entry |
| `/var/ossec/etc/rules/local_rules.xml` | Adds rules `100250`–`100294` |

Wazuh configuration changes are marked, backed up before each change, validated with Wazuh's configuration tests, and only then applied. Unrelated configuration is left alone.

## Important limitation: item names stay private

This is a feature of Bitwarden's zero-knowledge design, not a limitation of the integration: item names, notes, and passwords are encrypted client-side and are not exposed by the organisation event API. Alerts can include the opaque `itemId`, but never the plaintext item name.

Member identities are different: Bitwarden stores email addresses for account administration, so `actingUserId` and `memberId` can be resolved to a real address.

## Uninstall

```bash
sudo bash bitwarden-wazuh.sh uninstall          # asks for confirmation
sudo bash bitwarden-wazuh.sh uninstall --force  # for automation
```

Uninstalling removes the integration, including `organizations.json` and its API secrets, and reverses only the marked Wazuh configuration blocks.

## Security

- `organizations.json` contains plaintext API secrets. It is owned by `root` with mode `600`.
- Never commit a populated configuration file; share only the provided example file.
- If a key may have been exposed, rotate it immediately in the Bitwarden Admin Console.
- `/var/log/bitwarden` is `root:wazuh`, mode `2750`, allowing Wazuh to read events without making the directory world-readable.

## Repository layout

| File | Purpose |
|---|---|
| `bitwarden-wazuh.sh` | Installs, manages, updates, and removes the integration |


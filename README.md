# Vault Event Monitor

> An unofficial event-collection and alerting helper compatible with Bitwarden organisation event logs and Wazuh managers.

![Bash](https://img.shields.io/badge/Bash-5.0%2B-4EAA25?logo=gnubash&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.7%2B-3776AB?logo=python&logoColor=white)
![Wazuh compatible](https://img.shields.io/badge/Wazuh-compatible-1E90FF)
![Bitwarden compatible](https://img.shields.io/badge/Bitwarden-compatible-175DDC)

Vault Event Monitor collects Bitwarden organisation events, enriches them where possible, and writes JSON events for a Wazuh manager to monitor and classify with the included detection rules.

> **Unofficial project.** This project is an independent, third-party project. It is not affiliated with, sponsored by, endorsed by, or supported by Wazuh, Inc. or Bitwarden, Inc.
>
> **Trademark notice.** Bitwarden is a trademark of Bitwarden, Inc. Wazuh is a trademark of Wazuh, Inc. All other trademarks are the property of their respective owners. References to these products describe compatibility only and do not imply endorsement.

```text
Bitwarden organisation events → enriched JSON → Wazuh rules → actionable alerts
```

## Why use it?

- **Detect the events that matter.** Flag vault exports, organisation-vault purges, mass deletions, risky security-setting changes, and more.
- **Spot brute-force attempts.** Five failed logins from the same user within two minutes become a single correlated alert.
- **See people, not IDs.** Where Bitwarden makes the information available, user IDs are resolved to email addresses.
- **Start fast.** Run one script and follow the guided setup; no custom Wazuh rule design required.
- **Fit your environment.** Monitor one or many Bitwarden Cloud and self-hosted organisations from the same Wazuh manager.
- **Auditable source.** The Python poller and Wazuh rules are separate, reviewable files in this repository.
- **Choose how rules are updated.** Keep rules managed by the project or freeze them for local customisation.

## What an alert looks like

Raw events are not much fun to investigate:

```json
{ "type": 1007, "actingUserId": "affe2391-9e7b-4c94-90fd-b3fe00ad5a25" }
```

This helper can turn that into a high-signal alert:

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

## Get started

### Before you begin

You need:

- a working Wazuh manager (this project does not install Wazuh);
- `sudo` or root access on that manager;
- Python 3 with the third-party `requests` package available to that Python installation;
- outbound HTTPS access to Bitwarden or your self-hosted instance; and
- a Bitwarden organisation on a Teams or Enterprise plan, with an organisation API key.

### Python dependency

The poller imports the third-party Python package [`requests`](https://pypi.org/project/requests/). During `install` and `update`, the installer checks whether `python3` can import it. If not, it first attempts:

```bash
python3 -m pip install requests --break-system-packages
```

If that fails, it retries without `--break-system-packages`.

`--break-system-packages` allows `pip` to modify an operating-system-managed Python environment. This can cause dependency conflicts or make future system updates less predictable. On production hosts, consider installing `requests` first through your operating system's supported package manager (for example, a `python3-requests` package) so that the installer does not need to invoke `pip`.

The current installer and cron job use the system Python; they do not create a virtual environment. Uninstalling Vault Event Monitor does **not** remove `requests`, because it may be used by other software on the host.

### Install

Clone or download the **whole repository**. The installer requires its sibling source files, `bitwarden_wazuh_poller.py` and `bitwarden-wazuh-rules.xml`, to be next to it.

```bash
git clone https://github.com/timohissink/vault-event-monitor.git
cd vault-event-monitor
chmod +x vault-event-monitor.sh
sudo bash vault-event-monitor.sh
```

Choose **Install integration**, then enter your organisation name, client ID, client secret, and preferred rule-management mode.

Need an API key? In the Bitwarden web vault, go to **Admin Console → Settings → Organisation info → API Key**. You must be an organisation Owner or Admin.

## How it works

```text
Bitwarden Public API (one or more organisations)
                  │
                  ▼
      Python poller, every minute
                  │
                  ▼
    /var/log/bitwarden/events.log
                  │
                  ▼
       Wazuh JSON log monitoring
                  │
                  ▼
       Included detection rules
                  │
                  ▼
          Wazuh alerts
```

`vault-event-monitor.sh` orchestrates installation and management. It copies the separate poller source and rules file from the repository, creates the cron job and Wazuh `<localfile>` entry, and validates configuration before restarting Wazuh. It does not generate or embed the poller or rules source.

## Use the guided menu

```bash
sudo bash vault-event-monitor.sh
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

## Automate it

```bash
sudo bash vault-event-monitor.sh install --name "Acme Corp" --client-id "organization.xxxx" --client-secret "xxxx" --rules-mode managed
sudo bash vault-event-monitor.sh add-org --name "Acme NL" --client-id "organization.yyyy" --client-secret "yyyy"
sudo bash vault-event-monitor.sh remove-org --name "Acme NL"
sudo bash vault-event-monitor.sh status
sudo bash vault-event-monitor.sh run-now
sudo bash vault-event-monitor.sh update --rules-mode custom
sudo bash vault-event-monitor.sh uninstall --force
```

The script prompts only when attached to an interactive terminal, making it suitable for configuration management and CI.

## Self-hosted Bitwarden

Bitwarden Cloud is the default. For a self-hosted organisation, add your identity and API endpoints:

```bash
sudo bash vault-event-monitor.sh add-org \
  --name "Acme Self-Hosted" \
  --client-id "organization.yyyy" \
  --client-secret "yyyy" \
  --identity-url "https://bitwarden.acme.example.com/identity/connect/token" \
  --api-url "https://bitwarden.acme.example.com/api/public"
```

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

## Managing Wazuh rules

The detection rules are deployed as the dedicated file `/var/ossec/etc/rules/bitwarden-wazuh-rules.xml`, copied from `bitwarden-wazuh-rules.xml` in this repository. Choose the mode during installation, or pass `--rules-mode` to `install` or `update`.

| Mode | Behaviour |
|---|---|
| **managed** (default) | `update` refreshes the deployed rules file from the repository. Local edits are overwritten; a timestamped backup is created first. |
| **custom** | The file is deployed once and is not changed by `update`. You may customise rule IDs, levels, groups, descriptions, and mappings. If the repository rules change later, the update reports this and provides a `diff` command instead of overwriting your file. |

Switch to custom mode:

```bash
sudo bash vault-event-monitor.sh update --rules-mode custom
```

Check the current mode:

```bash
cat /etc/bitwarden-wazuh/.rules_mode
```

Before deploying rules, the installer checks other Wazuh rule files for use of IDs in the `100250`–`100294` range. It stops before changing the Wazuh configuration if it finds a conflict. If your Wazuh manager already uses that range, select `custom` mode and renumber the deployed rules to an unused range. The installer will not overwrite those local changes.

## Verify the installation

```bash
sudo bash vault-event-monitor.sh status
sudo tail -f /var/log/bitwarden/poller.log
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep '"description":"Bitwarden: '
```

To test the most recently collected event against the rules:

```bash
sudo tail -1 /var/log/bitwarden/events.log \
  | sudo /var/ossec/bin/wazuh-logtest 2>&1 | sed -n '/Phase 3/,$p'
```

## What gets installed

| Path | Purpose |
|---|---|
| `/opt/scripts/bitwarden_wazuh_poller.py` | Poller copied from the repository |
| `/etc/bitwarden-wazuh/organizations.json` | Credentials and organisation settings (mode `600`; never overwritten) |
| `/etc/bitwarden-wazuh/organizations.json.example` | Shareable configuration template |
| `/etc/bitwarden-wazuh/.rules_mode` | Selected rule-management mode |
| `/etc/bitwarden-wazuh/README.md` | Configuration documentation on the server |
| `/var/log/bitwarden/events.log` | Events monitored by Wazuh |
| `/var/log/bitwarden/poller.log` | Poller output written by cron |
| `/etc/cron.d/bitwarden-wazuh` | Runs the poller every minute as root |
| `/var/ossec/etc/ossec.conf` | Adds a marked Wazuh `<localfile>` entry |
| `/var/ossec/etc/rules/bitwarden-wazuh-rules.xml` | Dedicated rules file copied from the repository |

Both `ossec.conf` and the deployed rules file are backed up before changes and validated with Wazuh configuration tests before the manager restarts. Unrelated configuration is left untouched.

## Important limitation: item names stay private

Item names, notes, and passwords are encrypted client-side by Bitwarden and are not exposed by the organisation event API. Alerts can include the opaque `itemId`, but never the plaintext item name.

Member identities are different: Bitwarden stores email addresses for account administration, so `actingUserId` and `memberId` can be resolved to an email address.

## Uninstall

```bash
sudo bash vault-event-monitor.sh uninstall          # asks for confirmation
sudo bash vault-event-monitor.sh uninstall --force  # for automation
```

Uninstalling removes the integration, including `organizations.json` and its API secrets, the deployed rules file, and the marked Wazuh `<localfile>` block.

## Security

- `organizations.json` contains plaintext API secrets. It is owned by `root` with mode `600`.
- Never commit a populated configuration file; share only the provided example file.
- If a key may have been exposed, rotate it immediately in the Bitwarden Admin Console.
- `/var/log/bitwarden` is `root:wazuh`, mode `2750`, allowing Wazuh to read events without making the directory world-readable.

## Repository layout

| File | Purpose |
|---|---|
| `vault-event-monitor.sh` | Installer and management orchestrator |
| `bitwarden_wazuh_poller.py` | Python poller source |
| `bitwarden-wazuh-rules.xml` | Wazuh detection-rule source |

## License

Licensed under MIT.

See the `LICENSE` file for details.

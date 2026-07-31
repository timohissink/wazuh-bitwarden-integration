# Vault Event Monitor

> An unofficial integration for integrating Bitwarden event logs into Wazuh.

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
- **Automate confidently.** Every menu action also has a non-interactive command for Ansible, CI, or other automation.

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
- Python 3 and `pip` available to that Python installation;
- outbound HTTPS access to Bitwarden or your self-hosted instance; and
- a Bitwarden organisation on a Teams or Enterprise plan, with an organisation API key.

### Python dependency and system-package impact

The poller requires the third-party Python package [`requests`](https://pypi.org/project/requests/). If it is not already importable by `python3`, the installer attempts to install it with:

```bash
python3 -m pip install requests --break-system-packages
```

On systems that manage Python through the operating-system package manager, `--break-system-packages` permits `pip` to modify that managed environment. This can conflict with distribution-provided packages or affect other software that uses the same Python installation. Review this impact before running the installer, especially on production hosts.

If you prefer to avoid the installer performing that action, install and maintain `requests` through your operating system's supported package-management process before running the script, and confirm that `python3 -c "import requests"` succeeds. The current installer and cron job use the system `python3`; it does not create or use a virtual environment.

### Install

After renaming the repository to a neutral name such as `vault-event-monitor`, use its new URL and directory name:

```bash
git clone https://github.com/timohissink/vault-event-monitor
cd vault-event-monitor
chmod +x vault-event-monitor.sh
sudo bash vault-event-monitor.sh
```

Choose **Install integration** and enter your organisation name, client ID, and client secret.

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

The current release writes the poller to `/opt/scripts/bitwarden_wazuh_poller.py` from Python source embedded in the Bash installer. This keeps deployment self-contained, but means the generated poller should be reviewed together with `vault-event-monitor.sh`; changes made only to the installed `.py` file can be replaced when the installer is run again.

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
sudo bash vault-event-monitor.sh install --name "Acme Corp" --client-id "organization.xxxx" --client-secret "xxxx"
sudo bash vault-event-monitor.sh add-org --name "Acme NL" --client-id "organization.yyyy" --client-secret "yyyy"
sudo bash vault-event-monitor.sh remove-org --name "Acme NL"
sudo bash vault-event-monitor.sh status
sudo bash vault-event-monitor.sh run-now
sudo bash vault-event-monitor.sh update
sudo bash vault-event-monitor.sh uninstall --force
```

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

## Updating rules and configuration

The `update` command removes the marker-delimited project blocks from `/var/ossec/etc/ossec.conf` and `/var/ossec/etc/rules/local_rules.xml`, then recreates them from the installer. As a result, any manual edits **inside the project-managed rule block**—including rule IDs, levels, groups, descriptions, and mappings—will be overwritten by `install` or `update`.

Backups are created before configuration changes, but they are rollback copies rather than a way to preserve local customisations during an update. Keep custom rules outside the marked project block (for example, in a separate Wazuh rules file) and document or version-control them independently. Review the diff and retain a backup before running updates on a customised manager.

## Verify the installation

```bash
sudo bash vault-event-monitor.sh status
sudo tail -f /var/log/bitwarden/poller.log
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep '"description":"Bitwarden: '
```

## What gets installed

| Path | Purpose |
|---|---|
| `/opt/scripts/bitwarden_wazuh_poller.py` | Generated Python poller for the Bitwarden Public API |
| `/etc/bitwarden-wazuh/organizations.json` | Credentials and organisation settings (mode `600`) |
| `/etc/bitwarden-wazuh/organizations.json.example` | Shareable configuration template |
| `/etc/bitwarden-wazuh/README.md` | Configuration documentation on the server |
| `/var/log/bitwarden/events.log` | Events monitored by Wazuh |
| `/etc/cron.d/bitwarden-wazuh` | Runs the poller every minute |
| `/var/ossec/etc/ossec.conf` | Adds a marked Wazuh `<localfile>` entry |
| `/var/ossec/etc/rules/local_rules.xml` | Adds project-managed rules `100250`–`100294` |

## Security

- `organizations.json` contains plaintext API secrets. It is owned by `root` with mode `600`.
- Never commit a populated configuration file; share only the provided example file.
- If a key may have been exposed, rotate it immediately in the Bitwarden Admin Console.
- `/var/log/bitwarden` is `root:wazuh`, mode `2750`, allowing Wazuh to read events without making the directory world-readable.

## License

Licensed under MIT. See the `LICENSE` file for details.

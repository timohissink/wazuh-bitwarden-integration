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

"""Read-only investigation tools the investigator agent can call.

In a real company these would query a threat-intelligence platform, the HR /
identity system, the asset inventory (CMDB) and the change-management system.
Here they read small JSON files in the data/ folder.

Security design: every tool is READ-ONLY. The agent can look things up, but it
has no tool that changes anything (least privilege).
"""

import json
from pathlib import Path

DATA = Path(__file__).parent / "data"


def _load(name: str):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def lookup_threat_intel(indicator: str) -> dict:
    """Look up an IP address or a domain in the threat-intelligence database.

    Args:
        indicator: An IP address (for example '185.220.101.4') or a domain name (for example 'example.com').

    Returns:
        The reputation verdict (malicious, suspicious, benign, unknown or internal), tags and a short note.
    """
    record = _load("threat_intel.json").get(indicator.strip().lower())
    if record is None:
        return {"found": False, "indicator": indicator, "note": "No threat intelligence available for this indicator."}
    return {"found": True, "indicator": indicator, **record}


def get_user_info(username: str) -> dict:
    """Get information about a user or service account from the identity / HR system.

    Args:
        username: The account name, for example 'j.novak' or 'svc-reporting'.

    Returns:
        Department, role, employment status (for example active or leaving), usual locations and notes.
    """
    record = _load("users.json").get(username.strip().lower())
    if record is None:
        return {"found": False, "username": username}
    return {"found": True, "username": username, **record}


def get_asset_info(hostname: str) -> dict:
    """Get information about a computer or server from the asset inventory.

    Args:
        hostname: The host name, for example 'PRG-LT-0421'.

    Returns:
        Device type, owner, business criticality and notes.
    """
    record = _load("assets.json").get(hostname.strip().upper())
    if record is None:
        return {"found": False, "hostname": hostname}
    return {"found": True, "hostname": hostname, **record}


def search_change_tickets(entity: str) -> dict:
    """Search approved change tickets that mention a user, host, IP address or domain.

    Use this to check whether suspicious-looking activity was planned and approved.

    Args:
        entity: A username, host name, IP address or domain.

    Returns:
        The matching change tickets with their approved time window. An empty list means no approved change exists.
    """
    needle = entity.strip().lower()
    tickets = [t for t in _load("change_tickets.json") if needle in [r.lower() for r in t["related"]]]
    return {"entity": entity, "tickets": tickets}


# The only functions the agent is allowed to call. Anything else is refused.
TOOLS = {
    "lookup_threat_intel": lookup_threat_intel,
    "get_user_info": get_user_info,
    "get_asset_info": get_asset_info,
    "search_change_tickets": search_change_tickets,
}


def run_tool(name: str, args: dict) -> dict:
    """Execute a tool call requested by the model, safely."""
    func = TOOLS.get(name)
    if func is None:
        return {"error": f"Unknown tool '{name}'. Allowed tools: {list(TOOLS)}"}
    try:
        return func(**args)
    except Exception as error:  # wrong arguments etc. -> tell the model instead of crashing
        return {"error": f"Tool '{name}' failed: {error}"}

#!/usr/bin/env python3
"""Panorama Read-Only MCP Server — Query Palo Alto Networks Panorama via the PAN-OS XML API."""

import os
import re
import sys
import signal
import logging
import asyncio
import xml.etree.ElementTree as ET

import httpx
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Logging — all output goes to stderr so stdout stays clean for JSON-RPC
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("panorama-readonly")

# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------

def _handle_sigterm(*_args):
    logger.info("Received SIGTERM — shutting down")
    sys.exit(0)

signal.signal(signal.SIGTERM, _handle_sigterm)

# ---------------------------------------------------------------------------
# FastMCP init (no prompt parameter — rule #2)
# ---------------------------------------------------------------------------
mcp = FastMCP("panorama-readonly")

# ---------------------------------------------------------------------------
# Safety — blocked operational command prefixes
# ---------------------------------------------------------------------------
BLOCKED_OP_PREFIXES = [
    "<request", "<set", "<delete", "<debug", "<load",
    "<save", "<revert", "<schedule", "<test", "<clear",
    "<edit", "<configure", "<import", "<clone",
]


def _validate_readonly_op(cmd_xml: str) -> bool:
    """Return True only if the operational command is a safe read-only show command."""
    cmd_lower = cmd_xml.strip().lower()
    if not cmd_lower.startswith("<show>") and not cmd_lower.startswith("<show "):
        return False
    for prefix in BLOCKED_OP_PREFIXES:
        if prefix in cmd_lower:
            return False
    return True


# ---------------------------------------------------------------------------
# Safety — XPath input validation
# ---------------------------------------------------------------------------
# Names embedded inside XPath attribute values are validated against this
# pattern to prevent breakouts (single quotes, slashes, brackets, etc.).
# PAN-OS object names allow letters, digits, underscore, dot, hyphen, and
# spaces. Anything else is rejected.
_XPATH_NAME_RE = re.compile(r"^[A-Za-z0-9_.\- ]+$")

ALLOWED_PROFILE_TYPES = {
    "virus", "spyware", "vulnerability", "url-filtering",
    "file-blocking", "wildfire-analysis", "data-filtering",
    "dns-security",
}

ALLOWED_PREDEFINED_TYPES = {
    "application", "service", "application-tag",
    "threats/vulnerability", "threats/spyware",
}


def _validate_name(value: str, label: str) -> str:
    """Strip and validate a value embedded inside an XPath attribute. Raise ValueError on rejection."""
    name = value.strip()
    if not name:
        raise ValueError(f"{label} is required")
    if len(name) > 128:
        raise ValueError(f"{label} is too long (max 128 chars)")
    if not _XPATH_NAME_RE.match(name):
        raise ValueError(
            f"{label} contains invalid characters "
            f"(allowed: letters, digits, underscore, dot, hyphen, space)"
        )
    return name


def _validate_xpath(xpath: str) -> str:
    """Lightweight check for raw XPath input — must start with /config and stay short of pathological lengths."""
    xp = xpath.strip()
    if not xp:
        raise ValueError("xpath is required")
    if not xp.startswith("/config"):
        raise ValueError("xpath must start with /config")
    if len(xp) > 1024:
        raise ValueError("xpath is too long (max 1024 chars)")
    return xp


# ---------------------------------------------------------------------------
# Shared helper — make a read-only XML API request to Panorama
# ---------------------------------------------------------------------------

async def _panorama_request(params: dict, target_serial: str = "") -> ET.Element:
    """Make a read-only API request to Panorama and return parsed XML root."""
    host = os.environ.get("PANORAMA_HOST", "").strip()
    api_key = os.environ.get("PANORAMA_API_KEY", "").strip()
    verify_ssl = os.environ.get("PANORAMA_VERIFY_SSL", "yes").strip().lower() != "no"

    if not host:
        raise ValueError("PANORAMA_HOST environment variable is not set")
    if not api_key:
        raise ValueError("PANORAMA_API_KEY environment variable is not set")

    url = f"https://{host}/api/"
    headers = {"X-PAN-KEY": api_key}

    if target_serial.strip():
        params["target"] = target_serial.strip()

    timeout = httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0)
    async with httpx.AsyncClient(verify=verify_ssl, timeout=timeout) as client:
        try:
            response = await client.post(url, params=params, headers=headers)
            response.raise_for_status()
            root = ET.fromstring(response.text)
            status = root.attrib.get("status", "")
            if status != "success":
                msg_el = root.find(".//msg") or root.find(".//line")
                msg = msg_el.text if msg_el is not None and msg_el.text else "request rejected"
                raise ValueError(f"PAN-OS API error: {msg}")
            return root
        except httpx.HTTPStatusError as e:
            code = e.response.status_code
            if code in (401, 403):
                raise ValueError(f"HTTP {code}: authentication failed (check PANORAMA_API_KEY and admin role)")
            raise ValueError(f"HTTP {code}: request failed")
        except httpx.ConnectError:
            raise ValueError(f"Could not connect to Panorama at {host}")
        except httpx.TimeoutException:
            raise ValueError("Timed out waiting for Panorama response")
        except ET.ParseError:
            raise ValueError("Failed to parse XML response from Panorama")


# ---------------------------------------------------------------------------
# Shared helper — poll an async job until completion
# ---------------------------------------------------------------------------

async def _poll_job(job_id: str, job_type: str = "log", target_serial: str = "", timeout: int = 120) -> ET.Element:
    """Poll an async PAN-OS job until completion or timeout."""
    elapsed = 0
    while elapsed < timeout:
        params = {"type": job_type, "action": "get", "job-id": job_id}
        root = await _panorama_request(params, target_serial)
        status_el = root.find(".//job/status") or root.find(".//status")
        if status_el is not None and status_el.text == "FIN":
            return root
        await asyncio.sleep(2)
        elapsed += 2
    raise ValueError(f"Job {job_id} did not complete within {timeout} seconds")


# ---------------------------------------------------------------------------
# Helper — format XML element tree into readable text
# ---------------------------------------------------------------------------

def _xml_to_text(element: ET.Element, indent: int = 0) -> str:
    """Convert an XML element to indented readable text."""
    lines = []
    tag = element.tag
    text = (element.text or "").strip()
    attribs = " ".join(f'{k}="{v}"' for k, v in element.attrib.items())

    prefix = "  " * indent
    header = f"{prefix}{tag}"
    if attribs:
        header += f" [{attribs}]"
    if text:
        header += f": {text}"

    lines.append(header)
    for child in element:
        lines.append(_xml_to_text(child, indent + 1))
    return "\n".join(lines)


def _format_device_entry(entry: ET.Element) -> str:
    """Format a single managed device entry into a readable string."""
    fields = []
    name = entry.attrib.get("name", "N/A")
    fields.append(f"  Serial: {name}")
    for tag in ["hostname", "ip-address", "model", "sw-version", "ha-state",
                 "connected", "uptime", "family", "multi-vsys"]:
        el = entry.find(tag)
        if el is not None and el.text:
            fields.append(f"  {tag}: {el.text}")
    return "\n".join(fields)


def _format_rule_entry(entry: ET.Element) -> str:
    """Format a security/NAT rule entry into a readable string."""
    name = entry.attrib.get("name", "N/A")
    lines = [f"  Rule: {name}"]
    for tag in ["from", "to", "source", "destination", "application",
                 "service", "action", "disabled", "log-start", "log-end",
                 "description", "tag", "profile-setting",
                 "source-translation", "destination-translation"]:
        el = entry.find(tag)
        if el is not None:
            members = el.findall("member")
            if members:
                vals = ", ".join(m.text or "" for m in members)
                lines.append(f"    {tag}: {vals}")
            elif el.text:
                lines.append(f"    {tag}: {el.text}")
            else:
                # Sub-elements
                sub_text = _xml_to_text(el, 2)
                if sub_text.strip():
                    lines.append(sub_text)
    return "\n".join(lines)


# ===========================================================================
# TOOLS
# ===========================================================================

@mcp.tool()
async def get_system_info(target_serial: str = "") -> str:
    """Retrieve Panorama or firewall system information (hostname, model, serial, version, uptime)."""
    try:
        root = await _panorama_request(
            {"type": "op", "cmd": "<show><system><info></info></system></show>"},
            target_serial,
        )
        info = root.find(".//system")
        if info is None:
            return "No system info found in response"
        lines = ["System Information:"]
        for child in info:
            if child.text:
                lines.append(f"  {child.tag}: {child.text}")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_system_info: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_panorama_status() -> str:
    """Show Panorama HA status and general platform health information."""
    try:
        root = await _panorama_request(
            {"type": "op", "cmd": "<show><system><info></info></system></show>"}
        )
        info = root.find(".//system")
        if info is None:
            return "No system info found in response"
        lines = ["Panorama Status:"]
        important_tags = [
            "hostname", "ip-address", "model", "serial", "sw-version",
            "operational-mode", "multi-vsys", "devicename",
        ]
        for tag in important_tags:
            el = info.find(tag)
            if el is not None and el.text:
                lines.append(f"  {tag}: {el.text}")
        # HA fields
        for child in info:
            if "ha" in child.tag.lower() or "peer" in child.tag.lower():
                lines.append(f"  {child.tag}: {child.text or _xml_to_text(child, 1)}")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_panorama_status: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def list_managed_devices(connected_only: str = "no") -> str:
    """List all firewalls managed by Panorama with serial, hostname, IP, model, version, HA and connection state."""
    try:
        if connected_only.strip().lower() == "yes":
            cmd = "<show><devices><connected></connected></devices></show>"
        else:
            cmd = "<show><devices><all></all></devices></show>"
        root = await _panorama_request({"type": "op", "cmd": cmd})
        entries = root.findall(".//devices/entry") or root.findall(".//entry")
        if not entries:
            return "No managed devices found"
        lines = [f"Managed Devices ({len(entries)} found):"]
        for entry in entries:
            lines.append(_format_device_entry(entry))
            lines.append("  ---")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in list_managed_devices: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_device_groups() -> str:
    """List all device groups on Panorama and their member firewalls."""
    try:
        root = await _panorama_request(
            {"type": "op", "cmd": "<show><devicegroups></devicegroups></show>"}
        )
        entries = root.findall(".//devicegroups/entry") or root.findall(".//entry")
        if not entries:
            return "No device groups found"
        lines = ["Device Groups:"]
        for entry in entries:
            name = entry.attrib.get("name", "N/A")
            lines.append(f"\n  Device Group: {name}")
            devices = entry.findall(".//devices/entry")
            if devices:
                for dev in devices:
                    serial = dev.attrib.get("name", "N/A")
                    hostname_el = dev.find("hostname")
                    hostname = hostname_el.text if hostname_el is not None and hostname_el.text else "N/A"
                    connected_el = dev.find("connected")
                    connected = connected_el.text if connected_el is not None and connected_el.text else "N/A"
                    lines.append(f"    - {serial} ({hostname}) connected={connected}")
            else:
                lines.append("    (no devices assigned)")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_device_groups: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_templates() -> str:
    """List all templates and template stacks on Panorama with their assigned devices."""
    try:
        root = await _panorama_request(
            {"type": "op", "cmd": "<show><templates></templates></show>"}
        )
        entries = root.findall(".//templates/entry") or root.findall(".//entry")
        if not entries:
            return "No templates found"
        lines = ["Templates:"]
        for entry in entries:
            name = entry.attrib.get("name", "N/A")
            lines.append(f"\n  Template: {name}")
            devices = entry.findall(".//devices/entry")
            if devices:
                for dev in devices:
                    serial = dev.attrib.get("name", "N/A")
                    lines.append(f"    - {serial}")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_templates: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_running_config(xpath: str, target_serial: str = "") -> str:
    """Retrieve the active (running) configuration for a specific XPath (must start with /config)."""
    try:
        xp = _validate_xpath(xpath)
        root = await _panorama_request(
            {"type": "config", "action": "show", "xpath": xp},
            target_serial,
        )
        result = root.find(".//result")
        if result is None:
            result = root
        return f"Running Config ({xp}):\n{_xml_to_text(result)}"
    except Exception as e:
        logger.error(f"Error in get_running_config: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_candidate_config(xpath: str, target_serial: str = "") -> str:
    """Retrieve the candidate (uncommitted) configuration for a specific XPath (must start with /config)."""
    try:
        xp = _validate_xpath(xpath)
        root = await _panorama_request(
            {"type": "config", "action": "get", "xpath": xp},
            target_serial,
        )
        result = root.find(".//result")
        if result is None:
            result = root
        return f"Candidate Config ({xp}):\n{_xml_to_text(result)}"
    except Exception as e:
        logger.error(f"Error in get_candidate_config: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_security_rules(device_group: str = "", rule_type: str = "pre", target_serial: str = "") -> str:
    """Retrieve security policy rules from a device group (pre/post rules) or from a managed firewall."""
    try:
        if device_group.strip():
            dg = _validate_name(device_group, "device_group")
            rt = "pre-rulebase" if rule_type.strip().lower() == "pre" else "post-rulebase"
            xpath = (
                f"/config/devices/entry[@name='localhost.localdomain']"
                f"/device-group/entry[@name='{dg}']/{rt}/security/rules"
            )
        elif target_serial.strip():
            xpath = "/config/devices/entry/vsys/entry[@name='vsys1']/rulebase/security/rules"
        else:
            return "Error: Provide either device_group or target_serial"
        root = await _panorama_request(
            {"type": "config", "action": "show", "xpath": xpath},
            target_serial,
        )
        entries = root.findall(".//rules/entry") or root.findall(".//entry")
        if not entries:
            return "No security rules found"
        lines = [f"Security Rules ({len(entries)} found):"]
        for entry in entries:
            lines.append(_format_rule_entry(entry))
            lines.append("  ---")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_security_rules: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_nat_rules(device_group: str = "", rule_type: str = "pre", target_serial: str = "") -> str:
    """Retrieve NAT policy rules from a device group or managed firewall."""
    try:
        if device_group.strip():
            dg = _validate_name(device_group, "device_group")
            rt = "pre-rulebase" if rule_type.strip().lower() == "pre" else "post-rulebase"
            xpath = (
                f"/config/devices/entry[@name='localhost.localdomain']"
                f"/device-group/entry[@name='{dg}']/{rt}/nat/rules"
            )
        elif target_serial.strip():
            xpath = "/config/devices/entry/vsys/entry[@name='vsys1']/rulebase/nat/rules"
        else:
            return "Error: Provide either device_group or target_serial"
        root = await _panorama_request(
            {"type": "config", "action": "show", "xpath": xpath},
            target_serial,
        )
        entries = root.findall(".//rules/entry") or root.findall(".//entry")
        if not entries:
            return "No NAT rules found"
        lines = [f"NAT Rules ({len(entries)} found):"]
        for entry in entries:
            lines.append(_format_rule_entry(entry))
            lines.append("  ---")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_nat_rules: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_address_objects(location: str = "shared", target_serial: str = "") -> str:
    """Retrieve address objects from Panorama (shared or device-group) or a managed firewall."""
    try:
        if target_serial.strip():
            xpath = "/config/devices/entry/vsys/entry[@name='vsys1']/address"
        elif location.strip().lower() == "shared":
            xpath = "/config/shared/address"
        else:
            dg = _validate_name(location, "location")
            xpath = f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{dg}']/address"
        root = await _panorama_request(
            {"type": "config", "action": "show", "xpath": xpath},
            target_serial,
        )
        entries = root.findall(".//address/entry") or root.findall(".//entry")
        if not entries:
            return "No address objects found"
        lines = [f"Address Objects ({len(entries)} found):"]
        for entry in entries:
            name = entry.attrib.get("name", "N/A")
            value = ""
            for tag in ["ip-netmask", "ip-range", "ip-wildcard", "fqdn"]:
                el = entry.find(tag)
                if el is not None and el.text:
                    value = f"{tag}={el.text}"
                    break
            desc_el = entry.find("description")
            desc = f" — {desc_el.text}" if desc_el is not None and desc_el.text else ""
            lines.append(f"  {name}: {value}{desc}")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_address_objects: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_address_groups(location: str = "shared", target_serial: str = "") -> str:
    """Retrieve address group objects from Panorama or a managed firewall."""
    try:
        if target_serial.strip():
            xpath = "/config/devices/entry/vsys/entry[@name='vsys1']/address-group"
        elif location.strip().lower() == "shared":
            xpath = "/config/shared/address-group"
        else:
            dg = _validate_name(location, "location")
            xpath = f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{dg}']/address-group"
        root = await _panorama_request(
            {"type": "config", "action": "show", "xpath": xpath},
            target_serial,
        )
        entries = root.findall(".//address-group/entry") or root.findall(".//entry")
        if not entries:
            return "No address groups found"
        lines = [f"Address Groups ({len(entries)} found):"]
        for entry in entries:
            name = entry.attrib.get("name", "N/A")
            static_members = entry.findall("static/member")
            dynamic_el = entry.find("dynamic/filter")
            if static_members:
                members = ", ".join(m.text or "" for m in static_members)
                lines.append(f"  {name} (static): {members}")
            elif dynamic_el is not None and dynamic_el.text:
                lines.append(f"  {name} (dynamic): filter={dynamic_el.text}")
            else:
                lines.append(f"  {name}")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_address_groups: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_service_objects(location: str = "shared", target_serial: str = "") -> str:
    """Retrieve service objects (custom protocol/port definitions) from Panorama or a firewall."""
    try:
        if target_serial.strip():
            xpath = "/config/devices/entry/vsys/entry[@name='vsys1']/service"
        elif location.strip().lower() == "shared":
            xpath = "/config/shared/service"
        else:
            dg = _validate_name(location, "location")
            xpath = f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{dg}']/service"
        root = await _panorama_request(
            {"type": "config", "action": "show", "xpath": xpath},
            target_serial,
        )
        entries = root.findall(".//service/entry") or root.findall(".//entry")
        if not entries:
            return "No service objects found"
        lines = [f"Service Objects ({len(entries)} found):"]
        for entry in entries:
            name = entry.attrib.get("name", "N/A")
            parts = []
            for proto in ["tcp", "udp", "sctp"]:
                proto_el = entry.find(f"protocol/{proto}")
                if proto_el is not None:
                    port_el = proto_el.find("port")
                    src_port_el = proto_el.find("source-port")
                    port = port_el.text if port_el is not None and port_el.text else "any"
                    parts.append(f"{proto.upper()}/{port}")
                    if src_port_el is not None and src_port_el.text:
                        parts.append(f"src-port={src_port_el.text}")
            desc_el = entry.find("description")
            desc = f" — {desc_el.text}" if desc_el is not None and desc_el.text else ""
            lines.append(f"  {name}: {' '.join(parts)}{desc}")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_service_objects: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_security_profiles(profile_type: str, location: str = "shared") -> str:
    """Retrieve security profile configs (virus, spyware, vulnerability, url-filtering, file-blocking, wildfire-analysis, data-filtering, dns-security)."""
    try:
        pt = profile_type.strip()
        if pt not in ALLOWED_PROFILE_TYPES:
            return f"Error: profile_type must be one of: {', '.join(sorted(ALLOWED_PROFILE_TYPES))}"
        if location.strip().lower() == "shared":
            xpath = f"/config/shared/profiles/{pt}"
        else:
            dg = _validate_name(location, "location")
            xpath = f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{dg}']/profiles/{pt}"
        root = await _panorama_request(
            {"type": "config", "action": "show", "xpath": xpath}
        )
        result = root.find(".//result")
        if result is None:
            result = root
        return f"Security Profiles ({pt}):\n{_xml_to_text(result)}"
    except Exception as e:
        logger.error(f"Error in get_security_profiles: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def run_show_command(cmd_xml: str, target_serial: str = "") -> str:
    """Run any read-only operational 'show' command on Panorama or a managed firewall (cmd must start with <show>)."""
    if not cmd_xml.strip():
        return "Error: cmd_xml is required"
    if not _validate_readonly_op(cmd_xml):
        return "Error: Only read-only 'show' commands are allowed. The command must start with '<show>' and cannot contain blocked operations."
    try:
        root = await _panorama_request(
            {"type": "op", "cmd": cmd_xml.strip()},
            target_serial,
        )
        result = root.find(".//result")
        if result is None:
            result = root
        return f"Command Output:\n{_xml_to_text(result)}"
    except Exception as e:
        logger.error(f"Error in run_show_command: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_logs(log_type: str, query: str = "", nlogs: str = "20", skip: str = "0", direction: str = "backward") -> str:
    """Retrieve logs from Panorama (traffic, threat, url, wildfire, config, system, globalprotect, etc.)."""
    if not log_type.strip():
        return "Error: log_type is required (traffic, threat, url, wildfire, data, config, system, globalprotect, hipmatch, auth, decryption, userid, iptag)"
    try:
        params = {
            "type": "log",
            "log-type": log_type.strip(),
            "nlogs": nlogs.strip() or "20",
            "skip": skip.strip() or "0",
            "dir": direction.strip() or "backward",
        }
        if query.strip():
            params["query"] = query.strip()

        # Step 1: Initiate the log query job
        root = await _panorama_request(params)
        job_el = root.find(".//job")
        if job_el is None or not job_el.text:
            return "Error: No job ID returned from log query"

        job_id = job_el.text
        logger.info(f"Log query job initiated: {job_id}")

        # Step 2: Poll for completion
        result_root = await _poll_job(job_id, job_type="log")

        # Parse log entries
        log_entries = result_root.findall(".//log/logs/entry") or result_root.findall(".//logs/entry")
        if not log_entries:
            count_el = result_root.find(".//logs")
            count = count_el.attrib.get("count", "0") if count_el is not None else "0"
            if count == "0":
                return f"No {log_type} logs found matching the query"
            return f"Log query completed but no entries parsed. Raw:\n{_xml_to_text(result_root)}"

        lines = [f"{log_type.capitalize()} Logs ({len(log_entries)} entries):"]
        for entry in log_entries:
            lines.append("")
            for child in entry:
                if child.text:
                    lines.append(f"  {child.tag}: {child.text}")
            lines.append("  ---")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_logs: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_report(report_type: str, report_name: str = "", period: str = "last-24-hrs", topn: str = "10") -> str:
    """Retrieve predefined, dynamic, or custom reports from Panorama."""
    if not report_type.strip():
        return "Error: report_type is required (predefined, dynamic, custom)"
    try:
        params = {
            "type": "report",
            "reporttype": report_type.strip(),
        }
        if report_name.strip():
            params["reportname"] = report_name.strip()
        if report_type.strip() == "dynamic":
            params["period"] = period.strip() or "last-24-hrs"
            params["topn"] = topn.strip() or "10"

        # If no report_name, just list available reports
        if not report_name.strip():
            root = await _panorama_request(params)
            result = root.find(".//result")
            if result is None:
                result = root
            return f"Available {report_type} reports:\n{_xml_to_text(result)}"

        # Initiate report job
        root = await _panorama_request(params)
        job_el = root.find(".//job")
        if job_el is None or not job_el.text:
            # Some reports return data directly
            result = root.find(".//result")
            if result is None:
                result = root
            return f"Report ({report_name}):\n{_xml_to_text(result)}"

        job_id = job_el.text
        logger.info(f"Report job initiated: {job_id}")

        # Poll for completion
        result_root = await _poll_job(job_id, job_type="report")
        result = result_root.find(".//result") or result_root.find(".//report")
        if result is None:
            result = result_root
        return f"Report ({report_name}):\n{_xml_to_text(result)}"
    except Exception as e:
        logger.error(f"Error in get_report: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_predefined_objects(object_type: str, name_filter: str = "") -> str:
    """Retrieve predefined PAN-OS objects (application, service, application-tag, threats/vulnerability, threats/spyware)."""
    try:
        ot = object_type.strip()
        if ot not in ALLOWED_PREDEFINED_TYPES:
            return f"Error: object_type must be one of: {', '.join(sorted(ALLOWED_PREDEFINED_TYPES))}"
        if name_filter.strip():
            nf = _validate_name(name_filter, "name_filter")
            xpath = f"/config/predefined/{ot}/entry[@name='{nf}']"
        else:
            xpath = f"/config/predefined/{ot}"
        root = await _panorama_request(
            {"type": "config", "action": "get", "xpath": xpath}
        )
        result = root.find(".//result")
        if result is None:
            result = root
        # For large results, try to summarize
        entries = result.findall(".//entry")
        if entries and len(entries) > 50 and not name_filter.strip():
            lines = [f"Predefined {ot} ({len(entries)} objects). Showing first 50:"]
            for entry in entries[:50]:
                name = entry.attrib.get("name", "N/A")
                desc_el = entry.find("description")
                desc = f" — {desc_el.text}" if desc_el is not None and desc_el.text else ""
                lines.append(f"  {name}{desc}")
            lines.append(f"\n  ... and {len(entries) - 50} more. Use name_filter to look up specific objects.")
            return "\n".join(lines)
        return f"Predefined {ot}:\n{_xml_to_text(result)}"
    except Exception as e:
        logger.error(f"Error in get_predefined_objects: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_ha_status(target_serial: str = "") -> str:
    """Retrieve high-availability status for Panorama or a managed firewall."""
    try:
        root = await _panorama_request(
            {"type": "op", "cmd": "<show><high-availability><all></all></high-availability></show>"},
            target_serial,
        )
        result = root.find(".//result")
        if result is None:
            result = root
        return f"HA Status:\n{_xml_to_text(result)}"
    except Exception as e:
        logger.error(f"Error in get_ha_status: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_job_status(job_id: str, target_serial: str = "") -> str:
    """Check the status of an asynchronous job by its ID."""
    if not job_id.strip():
        return "Error: job_id is required"
    try:
        root = await _panorama_request(
            {"type": "op", "cmd": f"<show><jobs><id>{job_id.strip()}</id></jobs></show>"},
            target_serial,
        )
        result = root.find(".//result") or root.find(".//job")
        if result is None:
            result = root
        return f"Job {job_id} Status:\n{_xml_to_text(result)}"
    except Exception as e:
        logger.error(f"Error in get_job_status: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def export_device_state(target_serial: str = "") -> str:
    """Export the running configuration as XML for backup/review purposes (read-only export)."""
    try:
        root = await _panorama_request(
            {"type": "export", "category": "configuration"},
            target_serial,
        )
        result = root.find(".//result")
        if result is None:
            result = root
        # The config can be very large; summarize top-level nodes
        config = result.find(".//config") or result
        if config is not None:
            children = list(config)
            if len(children) > 0:
                lines = ["Configuration Export (top-level structure):"]
                for child in children:
                    count = len(list(child))
                    lines.append(f"  {child.tag} ({count} sub-elements)")
                lines.append(f"\nFull config is {len(ET.tostring(config, encoding='unicode'))} characters.")
                lines.append("Use get_running_config with a specific xpath to drill into sections.")
                return "\n".join(lines)
        return f"Configuration Export:\n{_xml_to_text(result)}"
    except Exception as e:
        logger.error(f"Error in export_device_state: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_config_audit(target_serial: str = "") -> str:
    """Show a summary of changes between the running and candidate configuration."""
    try:
        root = await _panorama_request(
            {"type": "op", "cmd": "<show><config><list><change-summary/></list></config></show>"},
            target_serial,
        )
        result = root.find(".//result")
        if result is None:
            result = root
        text = _xml_to_text(result)
        if not text.strip() or text.strip() == "result":
            return "No uncommitted changes detected"
        return f"Configuration Changes:\n{text}"
    except Exception as e:
        logger.error(f"Error in get_config_audit: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_commit_locks(target_serial: str = "") -> str:
    """Show any active commit locks on Panorama or a managed firewall."""
    try:
        root = await _panorama_request(
            {"type": "op", "cmd": "<show><commit-locks/></show>"},
            target_serial,
        )
        result = root.find(".//result")
        if result is None:
            result = root
        entries = result.findall(".//entry")
        if not entries:
            return "No active commit locks"
        lines = ["Active Commit Locks:"]
        for entry in entries:
            lines.append(_xml_to_text(entry, 1))
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_commit_locks: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_version_info(target_serial: str = "") -> str:
    """Show PAN-OS version, serial number, and model."""
    try:
        root = await _panorama_request(
            {"type": "version"},
            target_serial,
        )
        result = root.find(".//result")
        if result is None:
            result = root
        lines = ["Version Information:"]
        for child in result:
            if child.text:
                lines.append(f"  {child.tag}: {child.text}")
        if len(lines) == 1:
            return f"Version Info:\n{_xml_to_text(result)}"
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_version_info: {e}")
        return f"Error: {str(e)}"


# ---------------------------------------------------------------------------
# Resource — Panorama connection info
# ---------------------------------------------------------------------------

@mcp.resource("config://panorama-info")
def panorama_info() -> str:
    """Current Panorama connection details."""
    host = os.environ.get("PANORAMA_HOST", "(not set)")
    verify = os.environ.get("PANORAMA_VERIFY_SSL", "yes")
    key_set = "yes" if os.environ.get("PANORAMA_API_KEY", "").strip() else "no"
    return f"Host: {host}\nAPI Key configured: {key_set}\nSSL Verification: {verify}"


# ---------------------------------------------------------------------------
# Startup checks
# ---------------------------------------------------------------------------

def _startup_checks():
    """Warn about missing environment variables."""
    host = os.environ.get("PANORAMA_HOST", "").strip()
    api_key = os.environ.get("PANORAMA_API_KEY", "").strip()
    if not host:
        logger.warning("PANORAMA_HOST is not set — tools will fail until it is configured")
    if not api_key:
        logger.warning("PANORAMA_API_KEY is not set — generate one out of band (see README, Step 0) and store it via `docker mcp secret set PANORAMA_API_KEY=...`")
    verify = os.environ.get("PANORAMA_VERIFY_SSL", "yes").strip().lower()
    if verify == "no":
        logger.info("SSL verification is DISABLED (PANORAMA_VERIFY_SSL=no)")
    logger.info("Panorama Read-Only MCP Server starting up")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _startup_checks()
    mcp.run(transport="stdio")

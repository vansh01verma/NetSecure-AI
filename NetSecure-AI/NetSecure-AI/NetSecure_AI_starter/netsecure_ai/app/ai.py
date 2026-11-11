"""Deterministic, offline security assistant; no model provider is used."""
from __future__ import annotations

TOPICS = {
    "open": "An open TCP port means a connection was accepted at the time of the check. It does not prove a vulnerability. Confirm that the service is required, restrict access to trusted networks, and keep it patched.",
    "closed": "A closed_or_filtered result means the TCP connection was not established. This check cannot distinguish a closed port from one blocked by a firewall or filtered in transit.",
    "risk": "The risk score is a deterministic prioritization heuristic based on observed open ports. It is not a probability, CVSS score, or proof of compromise. Review the evidence and service context before taking action.",
    "severity": "Severity labels are heuristic categories assigned by this prototype to prioritize review. They are not a formal vulnerability severity rating and do not establish exploitability.",
    "cve": "A keyword search in NVD returns potentially related vulnerability records. A keyword match is not proof that a scanned host is affected. Verify the exact product, version, configuration, and applicable vendor advisory.",
    "remediation": "Start by confirming that the service is needed. Restrict access with host/network firewalls, expose administrative services only to trusted management networks, patch supported software, disable unused services, and retest after changes.",
    "limitations": "This tool performs bounded TCP reachability checks on explicitly authorized RFC1918 IPv4 targets. It does not fingerprint software versions, exploit services, test credentials, distinguish closed from filtered ports, or prove that a vulnerability exists.",
}


def answer(message: str) -> str:
    text = message.casefold()
    if any(w in text for w in ("cve", "nvd", "vulnerability database")):
        return TOPICS["cve"]
    if any(w in text for w in ("closed", "filtered", "not open")):
        return TOPICS["closed"]
    if any(w in text for w in ("severity", "critical", "high", "medium", "low")):
        return TOPICS["severity"]
    if any(w in text for w in ("risk score", "score", "risk")):
        return TOPICS["risk"]
    if any(w in text for w in ("fix", "remediat", "secure", "protect", "mitigat")):
        return TOPICS["remediation"]
    if any(w in text for w in ("limit", "limitation", "scope", "authorized", "authorization")):
        return TOPICS["limitations"]
    if any(w in text for w in ("open port", "port open", "tcp port")):
        return TOPICS["open"]
    return ("I can explain open and closed/filtered TCP ports, heuristic risk scores, severity labels, "
            "NVD/CVE search results, defensive remediation, and assessment limitations. "
            "Ask about one of those topics for a focused explanation.\n\n" + TOPICS["limitations"])

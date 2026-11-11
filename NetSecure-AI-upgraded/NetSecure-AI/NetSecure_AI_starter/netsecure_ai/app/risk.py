def assess(scan: dict) -> dict:
    findings = []
    weights = {22: (25, "medium"), 23: (55, "high"), 445: (45, "high"), 3306: (35, "medium"), 5432: (30, "medium"), 8080: (20, "low")}
    for item in scan["results"]:
        if item["state"] != "open":
            continue
        score, severity = weights.get(item["port"], (10, "low"))
        findings.append({"finding_id": f"NET-{scan['target'].replace('.', '-')}-{item['port']}", "target": scan["target"], "port": item["port"], "service": item["service_hint"], "severity": severity, "risk_score": score, "evidence": item["evidence"], "explanation": "The TCP port accepted a connection. This indicates exposure, not a confirmed vulnerability.", "remediation": "Confirm the service is required, restrict access with network controls, and keep the service securely configured and updated.", "confidence": "high for port reachability; low for vulnerability inference"})
    overall = max((f["risk_score"] for f in findings), default=0)
    return {"target": scan["target"], "overall_risk_score": overall, "findings": findings, "limitations": scan["limitations"]}

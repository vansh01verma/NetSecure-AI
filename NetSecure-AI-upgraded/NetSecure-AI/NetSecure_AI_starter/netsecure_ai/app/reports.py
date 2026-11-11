import csv, io, json

def render_report(data: dict, fmt: str):
    if fmt == "json":
        return json.dumps(data, indent=2), "application/json"
    if fmt == "csv":
        output = io.StringIO()
        fields = ["finding_id", "target", "port", "service", "severity", "risk_score", "evidence", "explanation", "remediation", "confidence"]
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data.get("findings", []))
        return output.getvalue(), "text/csv"
    raise ValueError("Supported report formats: json, csv")

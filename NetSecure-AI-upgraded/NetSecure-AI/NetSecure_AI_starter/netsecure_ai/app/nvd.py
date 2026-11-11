"""Small asynchronous client for the official NVD CVE API 2.0."""
import os
import httpx

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _cvss(metrics: dict) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
            return score, severity
    return None, None


async def search_cves(keyword: str, limit: int = 8) -> list[dict]:
    headers = {"apiKey": os.getenv("NVD_API_KEY", "")} if os.getenv("NVD_API_KEY") else {}
    params = {"keywordSearch": keyword, "resultsPerPage": limit}
    timeout = httpx.Timeout(12.0, connect=5.0)
    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        response = await client.get(NVD_URL, params=params)
        response.raise_for_status()
        payload = response.json()
    items = []
    for row in payload.get("vulnerabilities", []):
        cve = row.get("cve", {})
        desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        score, severity = _cvss(cve.get("metrics", {}))
        cve_id = cve.get("id", "")
        items.append({"id": cve_id, "published": cve.get("published"), "last_modified": cve.get("lastModified"),
                      "description": desc, "cvss_score": score, "severity": severity,
                      "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"})
    return items

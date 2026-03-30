"""
Join CVE -> earliest Reddit post time with NVD publish dates and compute lead/lag.

Inputs:
  - cve_summary.csv (from your previous script)

Outputs:
  - cve_lead_time.csv        (CVE + NVD dates + CVSS + lead_days)
  - nvd_fetch_failures.csv   (CVE + error)

Optional:
  Set NVD API key for better rate limits:
    Windows PowerShell:
      $env:NVD_API_KEY="YOUR_KEY"
      python nvd_join.py

NVD endpoint used:
  https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-....
"""

import os
import csv
import time
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List

import requests

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# -----------------------------
# Time helpers
# -----------------------------
def parse_iso_to_utc(dt_str: str) -> Optional[datetime]:
    """
    Parse ISO date/time strings (with or without Z / timezone) to UTC datetime.
    Returns None if invalid.
    """
    if not dt_str:
        return None
    s = dt_str.strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception:
        return None


def to_iso(dt: Optional[datetime]) -> str:
    return dt.isoformat() if dt else ""


# -----------------------------
# NVD helpers
# -----------------------------
def nvd_headers() -> Dict[str, str]:
    h = {"User-Agent": "CVE-Reddit-LeadTime/1.0"}
    key = os.getenv("NVD_API_KEY", "").strip()
    if key:
        h["apiKey"] = key
    return h


def safe_get_json(url: str, params: Dict[str, Any], timeout: int = 30, max_retries: int = 5) -> Dict[str, Any]:
    """
    Retry with backoff for rate limits / transient errors.
    """
    backoff = 1.0
    for attempt in range(1, max_retries + 1):
        r = requests.get(url, params=params, headers=nvd_headers(), timeout=timeout)

        # Success
        if r.status_code == 200:
            return r.json()

        # Rate limit / transient errors
        if r.status_code in (429, 500, 502, 503, 504):
            time.sleep(backoff)
            backoff = min(backoff * 2, 16)
            continue

        # Other errors: raise with body for debugging
        try:
            body = r.text[:500]
        except Exception:
            body = ""
        raise RuntimeError(f"NVD HTTP {r.status_code}: {body}")

    raise RuntimeError(f"NVD failed after {max_retries} retries (last status={r.status_code}).")


def extract_cvss(nvd_cve_obj: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Attempt to extract a CVSS base score, severity, and vector string from NVD CVE object.
    Prefers CVSS v3.1, then v3.0, then v2.
    Returns (score, severity, vector) as strings (empty if missing).
    """
    metrics = (nvd_cve_obj.get("metrics") or {})

    # Try v3.1
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        arr = metrics.get(key)
        if isinstance(arr, list) and arr:
            m0 = arr[0]  # primary
            cvss = (m0.get("cvssData") or {})
            score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity") or m0.get("baseSeverity")
            vector = cvss.get("vectorString")
            return (str(score) if score is not None else "", str(severity) if severity else "", str(vector) if vector else "")

    return ("", "", "")


def fetch_nvd_for_cve(cve_id: str) -> Dict[str, Any]:
    """
    Fetch a single CVE record from NVD by cveId.
    Returns a small dict with published, lastModified, cvss, etc.
    """
    payload = safe_get_json(NVD_BASE, params={"cveId": cve_id})
    vulns = payload.get("vulnerabilities")

    if not isinstance(vulns, list) or not vulns:
        # Sometimes NVD returns 0 results for very new or missing CVEs
        return {
            "cve": cve_id,
            "nvd_found": "false",
            "nvd_published": "",
            "nvd_last_modified": "",
            "cvss_score": "",
            "cvss_severity": "",
            "cvss_vector": "",
        }

    cve_obj = (vulns[0].get("cve") or {})
    published = cve_obj.get("published", "")
    last_modified = cve_obj.get("lastModified", "")

    score, severity, vector = extract_cvss(cve_obj)
    
    vendors = extract_vendors(cve_obj)

    return {
        "cve": cve_id,
        "nvd_found": "true",
        "nvd_published": published,
        "nvd_last_modified": last_modified,
        "cvss_score": score,
        "cvss_severity": severity,
        "cvss_vector": vector,
        "vendors": vendors,
    }


def extract_vendors(cve_obj: Dict[str, Any]) -> str:
    """
    Extract vendor/company names from NVD CPE (Common Platform Enumeration) data.
    Returns semicolon-separated list of vendors.
    """
    vendors_set = set()
    configurations = cve_obj.get("configurations", []) or []
    
    for config in configurations:
        nodes = config.get("nodes", []) or []
        for node in nodes:
            cpe_match = node.get("cpeMatch", []) or []
            for cpe in cpe_match:
                criteria = cpe.get("criteria", "")
                if criteria:
                    parts = criteria.split(":")
                    if len(parts) > 3:
                        vendor = parts[3]
                        if vendor and vendor not in ("*", "-"):
                            vendors_set.add(vendor)
    
    if not vendors_set:
        descriptions = cve_obj.get("description", []) or []
        for desc in descriptions:
            text = desc.get("value", "").lower()
            vendor_keywords = {
                "apple": "Apple", "google": "Google", "microsoft": "Microsoft",
                "linux": "Linux", "docker": "Docker", "mozilla": "Mozilla",
                "apache": "Apache", "nginx": "nginx", "oracle": "Oracle",
                "ibm": "IBM", "cisco": "Cisco", "intel": "Intel", "amd": "AMD",
                "nvidia": "NVIDIA", "redhat": "Red Hat", "ubuntu": "Ubuntu",
                "debian": "Debian", "fedora": "Fedora", "amazon": "Amazon",
                "cloudflare": "Cloudflare", "kubernetes": "Kubernetes",
                "nodejs": "Node.js", "python": "Python", "golang": "Go",
                "gitlab": "GitLab", "github": "GitHub", "jetbrains": "JetBrains",
                "wordpress": "WordPress", "joomla": "Joomla", "drupal": "Drupal",
            }
            for keyword, name in vendor_keywords.items():
                if keyword in text:
                    vendors_set.add(name)
    
    return ";".join(sorted(vendors_set))


# -----------------------------
# CSV IO
# -----------------------------
def read_cve_summary(path: str) -> List[Dict[str, str]]:
    with open(path, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: str, fieldnames: List[str], rows: List[Dict[str, Any]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


# -----------------------------
# Main join + lead time
# -----------------------------
def main():
    in_path = "cve_summary.csv"
    out_path = "cve_lead_time.csv"
    fail_path = "nvd_fetch_failures.csv"

    rows = read_cve_summary(in_path)

    out_rows: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []

    # Gentle pacing; if you have an API key you can reduce this.
    sleep_s = 0.6 if not os.getenv("NVD_API_KEY") else 0.2

    print(f"Loaded {len(rows)} CVEs from {in_path}")
    print("NVD API key:", "YES" if os.getenv("NVD_API_KEY") else "NO (slower rate limits)")

    for idx, r in enumerate(rows, start=1):
        cve_id = (r.get("cve") or "").strip()
        if not cve_id:
            continue

        earliest_iso = (r.get("earliest_post_iso_utc") or "").strip()
        earliest_dt = parse_iso_to_utc(earliest_iso)

        try:
            nvd = fetch_nvd_for_cve(cve_id)
        except Exception as e:
            failures.append({"cve": cve_id, "error": str(e)})
            print(f"[{idx}/{len(rows)}] {cve_id}: ERROR ({e})")
            time.sleep(sleep_s)
            continue

        nvd_pub_dt = parse_iso_to_utc(nvd.get("nvd_published", ""))
        lead_days = ""
        lead_hours = ""

        if earliest_dt and nvd_pub_dt:
            delta_seconds = (nvd_pub_dt - earliest_dt).total_seconds()
            lead_days = round(delta_seconds / 86400, 3)
            lead_hours = round(delta_seconds / 3600, 3)

        merged = {
            # From your summary
            "cve": cve_id,
            "post_count": r.get("post_count", ""),
            "earliest_post_iso_utc": earliest_iso,
            "earliest_post_epoch": r.get("earliest_post_epoch", ""),
            "subreddits": r.get("subreddits", ""),
            "example_urls": r.get("example_urls", ""),

            # From NVD
            "nvd_found": nvd.get("nvd_found", ""),
            "nvd_published": nvd.get("nvd_published", ""),
            "nvd_last_modified": nvd.get("nvd_last_modified", ""),
            "cvss_score": nvd.get("cvss_score", ""),
            "cvss_severity": nvd.get("cvss_severity", ""),
            "cvss_vector": nvd.get("cvss_vector", ""),
            "vendors": nvd.get("vendors", ""),

            # Computed
            "lead_days": lead_days,
            "lead_hours": lead_hours,
        }

        out_rows.append(merged)

        status = "FOUND" if nvd.get("nvd_found") == "true" else "NOT_FOUND"
        print(f"[{idx}/{len(rows)}] {cve_id}: {status} | lead_days={lead_days}")

        time.sleep(sleep_s)

    # Sort output: most positive lead first, then by post_count
    def sort_key(x):
        try:
            ld = float(x["lead_days"])
        except Exception:
            ld = -10**9
        try:
            pc = int(x["post_count"])
        except Exception:
            pc = 0
        return (-ld, -pc, x["cve"])

    out_rows_sorted = sorted(out_rows, key=sort_key)

    fieldnames = [
        "cve", "post_count",
        "earliest_post_iso_utc", "earliest_post_epoch",
        "nvd_found", "nvd_published", "nvd_last_modified",
        "cvss_score", "cvss_severity", "cvss_vector",
        "vendors",
        "lead_days", "lead_hours",
        "subreddits", "example_urls",
    ]
    write_csv(out_path, fieldnames, out_rows_sorted)

    write_csv(fail_path, ["cve", "error"], failures)

    print("\nDONE")
    print(f"Wrote: {out_path} ({len(out_rows_sorted)} rows)")
    print(f"Wrote: {fail_path} ({len(failures)} failures)")

    # Quick peek: top 10 leads
    print("\nTop 10 by lead_days (if available):")
    shown = 0
    for r in out_rows_sorted:
        if r["lead_days"] == "":
            continue
        print(f"- {r['cve']} | lead_days={r['lead_days']} | earliest={r['earliest_post_iso_utc']} | nvd={r['nvd_published']}")
        shown += 1
        if shown >= 10:
            break


if __name__ == "__main__":
    main()

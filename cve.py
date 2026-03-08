"""
Fetch CVE-related Reddit posts from releasetrain.io API and save:

1) reddit_cve_raw.json            (raw API data)
2) reddit_cve_posts.csv           (normalized rows, CVE extraction, timestamps)
3) reddit_cve_key_audit.csv       (quick audit: where CVE text was found)
4) cve_summary.csv                (CVE -> count, earliest post time, example URLs)

No pandas required. Uses requests + standard library only.

Run:
  python cve.py
"""

import re
import json
import csv
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set, Tuple, Iterable

import requests

BASE = "https://releasetrain.io/api/reddit/query/cve"
CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


# -----------------------------
# HTTP + payload helpers
# -----------------------------
def fetch_page(limit: int = 100, page: int = 1, show_count: bool = True, timeout: int = 30) -> Dict[str, Any]:
    params = {
        "limit": limit,
        "page": page,
        "showCount": "true" if show_count else "false",
    }
    r = requests.get(BASE, params=params, timeout=timeout)
    r.raise_for_status()
    return r.json()


def get_posts(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    d = payload.get("data")
    return d if isinstance(d, list) else []


def extract_field(d: Dict[str, Any], keys: List[str]) -> Optional[Any]:
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return None


# -----------------------------
# Recursive string walker
# -----------------------------
def iter_strings(obj: Any, prefix: str = "", max_depth: int = 6, _depth: int = 0) -> List[Tuple[str, str]]:
    """
    Recursively collect (path, string_value) from dict/list structures.
    Limits depth to avoid runaway recursion.
    """
    out: List[Tuple[str, str]] = []
    if _depth > max_depth:
        return out

    if isinstance(obj, str):
        out.append((prefix or "<root>", obj))
        return out

    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            out.extend(iter_strings(v, path, max_depth=max_depth, _depth=_depth + 1))
        return out

    if isinstance(obj, list):
        for i, v in enumerate(obj):
            path = f"{prefix}[{i}]" if prefix else f"[{i}]"
            out.extend(iter_strings(v, path, max_depth=max_depth, _depth=_depth + 1))
        return out

    return out


def extract_cves_from_post(post: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """
    Returns (sorted_cves, paths_with_cve_text)
    - CVEs are found across ALL nested string fields
    - paths_with_cve_text lists which paths contained CVE patterns
    """
    cves: Set[str] = set()
    paths: Set[str] = set()

    for path, s in iter_strings(post):
        matches = CVE_REGEX.findall(s)
        if matches:
            paths.add(path)
            for m in matches:
                cves.add(m.upper())

    return sorted(cves), sorted(paths)


# -----------------------------
# Timestamp parsing
# -----------------------------
def parse_datetime_to_utc(value: Any) -> Tuple[Optional[str], Optional[int]]:
    """
    Try to parse common timestamp formats into:
      - ISO string with timezone: created_iso_utc
      - epoch seconds: created_epoch

    Supports:
      - ISO strings: "2026-02-11T15:20:47" or "...Z" or "...+00:00"
      - epoch seconds (int/float or numeric string)
    """
    if value is None:
        return None, None

    # epoch numeric
    if isinstance(value, (int, float)):
        try:
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
            return dt.isoformat(), int(dt.timestamp())
        except Exception:
            return None, None

    s = str(value).strip()
    if not s:
        return None, None

    # numeric string epoch?
    if s.isdigit():
        try:
            dt = datetime.fromtimestamp(int(s), tz=timezone.utc)
            return dt.isoformat(), int(dt.timestamp())
        except Exception:
            pass

    # ISO string
    try:
        # handle trailing Z
        if s.endswith("Z"):
            s2 = s[:-1] + "+00:00"
        else:
            s2 = s

        dt = datetime.fromisoformat(s2)

        # If no tzinfo, assume UTC (common when field name includes _utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)

        return dt.isoformat(), int(dt.timestamp())
    except Exception:
        return None, None


def pick_best_created_field(post: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """
    Find a likely "created" timestamp field and parse it.
    Returns (created_field_name, created_iso_utc, created_epoch)

    Tries common field names first.
    Falls back to searching any key that looks like it might be created time.
    """
    preferred_keys = [
        "created_utc", "createdUtc", "created_at", "createdAt", "created",
        "timestamp", "timeCreated"
    ]

    for k in preferred_keys:
        if k in post:
            iso, epoch = parse_datetime_to_utc(post.get(k))
            if iso and epoch is not None:
                return k, iso, epoch

    # fallback: look for any key containing "created"
    for k, v in post.items():
        if isinstance(k, str) and "created" in k.lower():
            iso, epoch = parse_datetime_to_utc(v)
            if iso and epoch is not None:
                return k, iso, epoch

    return None, None, None


def pick_best_updated_field(post: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    preferred_keys = ["updatedAt", "updated_at", "lastUpdated", "last_updated", "modified", "modifiedAt"]
    for k in preferred_keys:
        if k in post:
            iso, epoch = parse_datetime_to_utc(post.get(k))
            if iso and epoch is not None:
                return k, iso, epoch
    return None, None, None


# -----------------------------
# Normalization + outputs
# -----------------------------
def normalize_post(p: Dict[str, Any]) -> Dict[str, Any]:
    title = extract_field(p, ["title", "postTitle", "name"]) or ""
    body = extract_field(p, ["selftext", "body", "text", "content"]) or ""
    url = extract_field(p, ["url", "permalink", "link"]) or ""
    subreddit = extract_field(p, ["subreddit", "sub"]) or ""
    author = extract_field(p, ["author", "username", "user"]) or ""
    score = extract_field(p, ["score", "upvotes", "ups"])
    post_id = extract_field(p, ["id", "post_id", "postId"]) or ""

    cves, cve_paths = extract_cves_from_post(p)

    created_field, created_iso, created_epoch = pick_best_created_field(p)
    updated_field, updated_iso, updated_epoch = pick_best_updated_field(p)

    return {
        "post_id": post_id,
        "subreddit": subreddit,
        "author": author,
        "score": score,
        "title": title,
        "body": body,
        "url": url,

        "cves": ";".join(cves),
        "cve_count": len(cves),
        "cve_paths": ";".join(cve_paths),

        "created_field": created_field or "",
        "created_iso_utc": created_iso or "",
        "created_epoch": created_epoch if created_epoch is not None else "",
        "updated_field": updated_field or "",
        "updated_iso_utc": updated_iso or "",
        "updated_epoch": updated_epoch if updated_epoch is not None else "",
    }


def explode_cves(cve_str: str) -> List[str]:
    if not cve_str:
        return []
    return [c.strip() for c in cve_str.split(";") if c.strip()]


def write_csv(path: str, fieldnames: List[str], rows: Iterable[Dict[str, Any]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def build_cve_summary(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Create one row per CVE:
      - post_count
      - earliest_post_iso_utc
      - earliest_post_epoch
      - example_urls (up to 5)
      - subreddits (unique)
    """
    by_cve: Dict[str, Dict[str, Any]] = {}

    for r in rows:
        cves = explode_cves(r.get("cves", ""))
        if not cves:
            continue

        created_epoch = r.get("created_epoch")
        try:
            created_epoch_int = int(created_epoch) if created_epoch != "" else None
        except Exception:
            created_epoch_int = None

        created_iso = r.get("created_iso_utc", "") or ""
        url = r.get("url", "") or ""
        subreddit = r.get("subreddit", "") or ""

        for cve in cves:
            if cve not in by_cve:
                by_cve[cve] = {
                    "cve": cve,
                    "post_count": 0,
                    "earliest_post_epoch": None,
                    "earliest_post_iso_utc": "",
                    "example_urls": [],
                    "subreddits": set(),
                }

            agg = by_cve[cve]
            agg["post_count"] += 1
            agg["subreddits"].add(subreddit)

            if url and len(agg["example_urls"]) < 5 and url not in agg["example_urls"]:
                agg["example_urls"].append(url)

            if created_epoch_int is not None:
                if agg["earliest_post_epoch"] is None or created_epoch_int < agg["earliest_post_epoch"]:
                    agg["earliest_post_epoch"] = created_epoch_int
                    agg["earliest_post_iso_utc"] = created_iso

    # finalize
    out = []
    for cve, agg in sorted(by_cve.items(), key=lambda x: (-x[1]["post_count"], x[0])):
        out.append({
            "cve": agg["cve"],
            "post_count": agg["post_count"],
            "earliest_post_iso_utc": agg["earliest_post_iso_utc"],
            "earliest_post_epoch": agg["earliest_post_epoch"] if agg["earliest_post_epoch"] is not None else "",
            "subreddits": ";".join(sorted(s for s in agg["subreddits"] if s)),
            "example_urls": ";".join(agg["example_urls"]),
        })
    return out


def main():
    # Pull everything in one request (works since totalCount is small; still safe if it grows a bit)
    payload = fetch_page(limit=100, page=1, show_count=True)
    total_count = payload.get("totalCount")
    posts = get_posts(payload)

    print(f"Fetched: {len(posts)} posts (totalCount={total_count})")

    # Save raw JSON for reproducibility
    with open("reddit_cve_raw.json", "w", encoding="utf-8") as f:
        json.dump(posts, f, indent=2, ensure_ascii=False)

    # Normalize
    rows = [normalize_post(p) for p in posts]

    # Save posts CSV
    posts_fields = [
        "post_id", "subreddit", "author", "score",
        "created_field", "created_iso_utc", "created_epoch",
        "updated_field", "updated_iso_utc", "updated_epoch",
        "title", "body", "url",
        "cves", "cve_count", "cve_paths",
    ]
    write_csv("reddit_cve_posts.csv", posts_fields, rows)

    # Save audit CSV
    audit_rows = []
    for r in rows:
        audit_rows.append({
            "post_id": r["post_id"],
            "subreddit": r["subreddit"],
            "created_iso_utc": r["created_iso_utc"],
            "title": (r["title"] or "")[:140],
            "cves": r["cves"],
            "cve_paths": (r["cve_paths"] or "")[:320],
            "url": r["url"],
        })
    audit_fields = ["post_id", "subreddit", "created_iso_utc", "title", "cves", "cve_paths", "url"]
    write_csv("reddit_cve_key_audit.csv", audit_fields, audit_rows)

    # Build and save CVE summary
    cve_summary = build_cve_summary(rows)
    cve_fields = ["cve", "post_count", "earliest_post_iso_utc", "earliest_post_epoch", "subreddits", "example_urls"]
    write_csv("cve_summary.csv", cve_fields, cve_summary)

    # Print quick stats
    extracted = sum(1 for r in rows if int(r["cve_count"] or 0) > 0)
    print("\nDONE")
    print(f"API totalCount: {total_count}")
    print("Saved files: reddit_cve_raw.json, reddit_cve_posts.csv, reddit_cve_key_audit.csv, cve_summary.csv")
    print(f"Posts with extracted CVE IDs: {extracted}/{len(rows)}")

    print("\nSample (first 8):")
    for r in rows[:8]:
        print(f"- r/{r['subreddit']}: {r['title'][:70]} | created={r['created_iso_utc']} | CVEs: {r['cves']}")

    print("\nTop CVEs by post_count (up to 10):")
    for s in cve_summary[:10]:
        print(f"- {s['cve']}: {s['post_count']} posts | earliest={s['earliest_post_iso_utc']}")

if __name__ == "__main__":
    main()

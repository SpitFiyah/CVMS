"""Normalize one authentic NVD CVE response item into staging records."""

from datetime import datetime, timezone
from decimal import Decimal
import json
import re
from urllib.parse import urlsplit
from uuid import UUID

from .cpe_parser import product_key, split_cpe


CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
METRICS = (
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)
BOUNDS = {
    "versionStartIncluding": "version_start_incl",
    "versionStartExcluding": "version_start_excl",
    "versionEndIncluding": "version_end_incl",
    "versionEndExcluding": "version_end_excl",
}


def required_text(value, label, max_bytes=None):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must contain text")
    if max_bytes is not None and len(value.encode("utf-8")) > max_bytes:
        raise ValueError(f"{label} exceeds {max_bytes} bytes")
    return value


def optional_text(value, label, max_bytes=None):
    if value is None or value == "":
        return None
    return required_text(value, label, max_bytes)


def utc_timestamp(value, label):
    result = datetime.fromisoformat(required_text(value, label))
    if result.tzinfo is not None:
        result = result.astimezone(timezone.utc).replace(tzinfo=None)
    if result.microsecond % 1000:
        raise ValueError(f"{label} exceeds millisecond precision")
    return result.isoformat(timespec="milliseconds")


def list_of(objects, key):
    items = objects.get(key, [])
    if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
        raise ValueError(f"{key} must be an array of objects")
    return items


def parse_metric(metrics):
    for group, version in METRICS:
        choices = list_of(metrics, group)
        if not choices:
            continue
        metric = min(
            choices,
            key=lambda row: (
                row.get("source") != "nvd@nist.gov",
                row.get("type") != "Primary",
                str(row.get("source")),
                json.dumps(row, sort_keys=True),
            ),
        )
        data = metric["cvssData"]
        if data.get("version") != version:
            raise ValueError("CVSS version disagrees with metric group")
        base_score = data["baseScore"]
        if type(base_score) not in (int, float):
            raise ValueError("CVSS score must be numeric")
        score = Decimal(str(base_score))
        if not score.is_finite() or not 0 <= score <= 10 or score != round(score, 1):
            raise ValueError("Invalid CVSS base score")
        return {
            "cvss_version": version,
            "cvss_score": str(round(score, 1)),
            "cvss_source": required_text(metric.get("source"), "metric source", 150),
            "severity": optional_text(data.get("baseSeverity", metric.get("baseSeverity")), "severity", 20),
        }
    return dict(cvss_version=None, cvss_score=None, cvss_source=None, severity=None)


def project_criteria(node, prefix):
    for index, item in enumerate(list_of(node, "cpeMatch")):
        path = required_text(f"{prefix}/cpeMatch/{index}", "criterion path", 250)
        cpe = required_text(item["criteria"], "CPE criterion", 1000)
        part, vendor, product = product_key(split_cpe(cpe))
        if type(item.get("vulnerable")) is not bool:
            raise ValueError("CPE vulnerable flag must be Boolean")
        bounds = {dest: optional_text(item.get(src), src, 100) for src, dest in BOUNDS.items()}
        if (
            bounds["version_start_incl"] and bounds["version_start_excl"]
            or bounds["version_end_incl"] and bounds["version_end_excl"]
        ):
            raise ValueError("Conflicting CPE version boundaries")
        match_id = optional_text(item.get("matchCriteriaId"), "match criteria ID", 36)
        yield {
            "criterion_path": path,
            "cpe_part": part,
            "cpe_vendor": optional_text(vendor, "CPE vendor", 150),
            "cpe_product": optional_text(product, "CPE product", 200),
            "cpe_uri": cpe,
            "match_criteria_id": str(UUID(match_id)) if match_id else None,
            "vulnerable_flag": "Y" if item["vulnerable"] else "N",
            **bounds,
        }
    for children_key in ("nodes", "children"):
        for index, child in enumerate(list_of(node, children_key)):
            yield from project_criteria(child, f"{prefix}/{children_key}/{index}")


def parse_cve(item):
    cve = item["cve"]
    identifier = required_text(cve["id"], "CVE identifier", 25)
    if not CVE_ID.fullmatch(identifier):
        raise ValueError("Invalid CVE identifier")
    published = cve.get("published")
    description = next(
        (row.get("value") for row in list_of(cve, "descriptions") if row.get("lang") == "en"), None
    )
    status = optional_text(cve.get("vulnStatus"), "NVD status", 50)
    # A rejected record can supersede an earlier published record. Keep the CVE
    # status and current references while retiring its applicability projection.
    configs = [] if status == "Rejected" else list_of(cve, "configurations")
    references = {}
    for ref in list_of(cve, "references"):
        url = required_text(ref["url"], "reference URL", 1000)
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https", "ftp"} or not parsed.hostname:
            raise ValueError("Reference URL must be HTTP, HTTPS or FTP")
        source = required_text(ref["source"], "reference source", 200)
        tags = ref.get("tags", [])
        if not isinstance(tags, list):
            raise ValueError("Reference tags must be an array")
        references.setdefault((url, source), set()).update(
            required_text(tag, "reference tag", 100) for tag in tags
        )

    return {
        "vulnerability": {
            "cve_id": identifier,
            "description": optional_text(description, "description"),
            "published_date": utc_timestamp(published, "published") if published else None,
            "last_modified_date": utc_timestamp(cve["lastModified"], "lastModified"),
            "nvd_status": status,
            **parse_metric(cve.get("metrics", {})),
        },
        "app_config": [
            {"config_ordinal": index, "original_config": json.dumps(config, ensure_ascii=False)}
            for index, config in enumerate(configs)
        ],
        "criterion": [
            {"config_ordinal": index, **criterion}
            for index, config in enumerate(configs)
            for criterion in project_criteria(config, "")
        ],
        "reference": [
            {"reference_url": url, "reference_source": source}
            for url, source in sorted(references)
        ],
        "reference_tag": [
            {"reference_url": url, "reference_source": source, "tag": tag}
            for (url, source), tags in sorted(references.items())
            for tag in sorted(tags)
        ],
    }

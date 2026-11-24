"""Write a reproducible, reviewable staging batch with manifest and rejects."""

import argparse
import csv
from datetime import datetime, timezone
from hashlib import sha256
import json
from io import BytesIO
from pathlib import Path

from .cve_parser import parse_cve
from .nvd_client import ENDPOINTS, NvdClient


FIELDS = {
    "vulnerability": ("cve_id", "description", "cvss_version", "cvss_score", "cvss_source",
                      "severity", "published_date", "last_modified_date", "revision_hash", "nvd_status"),
    "app_config": ("config_ordinal", "original_config"),
    "criterion": ("config_ordinal", "criterion_path", "cpe_part", "cpe_vendor", "cpe_product",
                  "cpe_uri", "match_criteria_id", "vulnerable_flag", "version_start_incl",
                  "version_start_excl", "version_end_incl", "version_end_excl"),
    "reference": ("reference_url", "reference_source"),
    "reference_tag": ("reference_url", "reference_source", "tag"),
    "reject": ("external_id", "reason"),
}


def write_batch(client, output, filters, *, page_size=20, max_records=50):
    output.mkdir(parents=True)
    raw_dir = output / "raw"
    raw_dir.mkdir()
    raw_pages = []

    def archive(start, raw):
        path = raw_dir / f"cves-{start:08d}.json"
        path.write_bytes(raw)
        raw_pages.append({"start_index": start, "file": str(path.relative_to(output)),
                          "sha256": sha256(raw).hexdigest()})

    rows = {name: [] for name in FIELDS}
    candidates = {}
    retrieved = 0
    for start, items in client.pages("cves", "vulnerabilities", filters,
                                     page_size=page_size, max_records=max_records, archive=archive):
        for index, item in enumerate(items):
            locator = f"cves-{start:08d}.json#/vulnerabilities/{index}"
            retrieved += 1
            try:
                parsed = parse_cve(item)
            except (AttributeError, KeyError, RecursionError, TypeError, ValueError) as error:
                obj = item.get("cve", {}) if isinstance(item, dict) else {}
                identifier = obj.get("id") if isinstance(obj, dict) else None
                rows["reject"].append({"row_locator": locator,
                                       "external_id": str(identifier or "")[:100],
                                       "reason": str(error)[:1000]})
                continue
            identifier = parsed["vulnerability"]["cve_id"]
            candidates.setdefault(identifier, []).append((locator, parsed))

    for identifier, versions in candidates.items():
        versions.sort(key=lambda item: item[1]["vulnerability"]["last_modified_date"], reverse=True)
        chosen = versions[0][1]
        latest_revision = chosen["vulnerability"]["last_modified_date"]
        conflicting = any(parsed["vulnerability"]["last_modified_date"] == latest_revision and parsed != chosen
                          for _, parsed in versions[1:])
        for index, (locator, parsed) in enumerate(versions):
            if conflicting or index:
                rows["reject"].append({
                    "row_locator": locator,
                    "external_id": identifier,
                    "reason": "Conflicting same-timestamp revisions" if conflicting else "Duplicate CVE in batch",
                })
                continue
            digest = sha256(json.dumps(parsed, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
            parsed["vulnerability"]["revision_hash"] = digest
            for name, values in parsed.items():
                records = [values] if name == "vulnerability" else values
                rows[name].extend({"row_locator": locator, **record} for record in records)

    files = {}
    for name, fields in FIELDS.items():
        filename = f"{name}.csv"
        path = output / filename
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=("row_locator", *fields))
            writer.writeheader()
            writer.writerows(rows[name])
        files[filename] = sha256(path.read_bytes()).hexdigest()
    manifest = {
        "format_version": 1,
        "source_url": ENDPOINTS["cves"],
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "filters": filters,
        "retrieved": retrieved,
        "accepted": len(rows["vulnerability"]),
        "rejected": len(rows["reject"]),
        "files": files,
        "raw_pages": raw_pages,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New batch directory")
    parser.add_argument("--cve-id")
    parser.add_argument("--cpe-name")
    parser.add_argument("--page-size", type=int, default=20)
    parser.add_argument("--max-records", type=int, default=50)
    parser.add_argument("--snapshot", type=Path, help="Replay one previously captured NVD first page")
    args = parser.parse_args()
    filters = {name: value for name, value in (("cveId", args.cve_id), ("cpeName", args.cpe_name)) if value}
    if args.snapshot:
        if filters:
            parser.error("--snapshot cannot be combined with live API filters")
        snapshot = args.snapshot.read_bytes()
        received = json.loads(snapshot)
        page_length = len(received["vulnerabilities"])
        if received["startIndex"] != 0 or not 1 <= page_length <= 100:
            parser.error("--snapshot must contain the first page with 1–100 records")
        client = NvdClient(opener=lambda *args, **kwargs: BytesIO(snapshot))
        args.max_records = args.page_size = page_length
    else:
        client = NvdClient.from_environment()
    manifest = write_batch(client, args.output, filters,
                           page_size=args.page_size, max_records=args.max_records)
    print(json.dumps({key: manifest[key] for key in ("retrieved", "accepted", "rejected")}))


if __name__ == "__main__":
    main()

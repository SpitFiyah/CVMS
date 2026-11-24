"""Check supplied CPE names against the official NVD CPE Dictionary."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

from .cpe_parser import split_cpe
from .nvd_client import ENDPOINTS, NvdClient


def reconcile(client, output, cpe_names, *, max_records=100):
    """Archive dictionary pages and report exact matches with their provenance."""
    if max_records < 1:
        raise ValueError("max_records must be positive")
    names = list(dict.fromkeys(cpe_names))
    if not names:
        raise ValueError("Supply at least one CPE name")
    components = {name: split_cpe(name) for name in names}

    output.mkdir(parents=True)
    checks = []
    for query_index, name in enumerate(names):
        raw_pages = []
        matches = {}
        totals = []
        reviewed = 0

        def archive(start, raw):
            filename = f"cpes-{query_index:04d}-{start:08d}.json"
            (output / filename).write_bytes(raw)
            totals.append(json.loads(raw)["totalResults"])
            raw_pages.append({"file": filename, "sha256": sha256(raw).hexdigest()})

        for _, products in client.pages(
            "cpes", "products", {"cpeMatchString": name},
            page_size=min(max_records, 100), max_records=max_records, archive=archive,
        ):
            reviewed += len(products)
            for product in products:
                record = product["cpe"]
                if split_cpe(record["cpeName"]) != components[name]:
                    continue
                identifier = record["cpeNameId"]
                deprecated = record["deprecated"]
                if not isinstance(identifier, str) or not identifier or type(deprecated) is not bool:
                    raise ValueError("Malformed CPE dictionary identity or deprecation flag")
                if identifier in matches and matches[identifier] != deprecated:
                    raise ValueError("Conflicting CPE dictionary deprecation flags")
                matches[identifier] = deprecated

        total = max(totals)
        checks.append({
            "query": name,
            "reviewed": reviewed,
            "reported_results": total,
            "complete": len(set(totals)) == 1 and reviewed >= total,
            "exact_matches": [
                {"cpe_name_id": identifier, "deprecated": deprecated}
                for identifier, deprecated in sorted(matches.items())
            ],
            "raw_pages": raw_pages,
        })
    report = {"endpoint": ENDPOINTS["cpes"], "checks": checks}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New archive directory")
    parser.add_argument("cpe_names", nargs="+", help="CPE 2.3 formatted names")
    parser.add_argument("--max-records", type=int, default=100, help="Result cap per queried name")
    args = parser.parse_args()
    if args.max_records < 1:
        parser.error("--max-records must be positive")
    report = reconcile(NvdClient.from_environment(), args.output, args.cpe_names,
                       max_records=args.max_records)
    print(f"Checked {len(report['checks'])} CPE names. See {args.output / 'report.json'}.")


if __name__ == "__main__":
    main()

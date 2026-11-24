import csv
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

from etl.cpe_parser import product_key, split_cpe
from etl.cve_parser import parse_cve
from etl.importer import read_batch
from etl.normalizer import write_batch
from etl.nvd_client import NvdClient


def example():
    """Construct parser test input that is never included in project data."""
    return {
        "cve": {
            "id": "CVE-9999-0001",
            "lastModified": "2024-01-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": 'test, "description"\nsecond line'}],
            "references": [
                {"url": "https://example.invalid/test", "source": "test", "tags": ["Advisory"]},
                {"url": "https://example.invalid/test", "source": "test", "tags": ["Advisory", "Patch"]},
            ],
        }
    }


class ParserTests(TestCase):
    def test_missing_metrics_and_deduplicated_reference_tags(self):
        parsed = parse_cve(example())
        self.assertIsNone(parsed["vulnerability"]["cvss_score"])
        self.assertIsNone(parsed["vulnerability"]["cvss_version"])
        self.assertEqual(len(parsed["reference"]), 1)
        self.assertEqual([row["tag"] for row in parsed["reference_tag"]], ["Advisory", "Patch"])

    def test_invalid_identifier(self):
        item = example()
        item["cve"]["id"] = "cve-2024-0101"
        with self.assertRaisesRegex(ValueError, "identifier"):
            parse_cve(item)

    def test_metric_selection_and_range(self):
        item = example()
        data = {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL"}
        metric = {"source": "nvd@nist.gov", "type": "Primary", "cvssData": data}
        item["cve"]["metrics"] = {"cvssMetricV31": [metric]}
        self.assertEqual(parse_cve(item)["vulnerability"]["cvss_score"], "9.8")
        for score in (11, True, float("nan"), 7.01):
            data["baseScore"] = score
            with self.subTest(score=score), self.assertRaises(ValueError):
                parse_cve(item)

    def test_configuration_preserves_context(self):
        item = example()
        criterion = {"criteria": "cpe:2.3:o:vendor:os:*:*:*:*:*:*:*:*", "vulnerable": False,
                     "versionEndExcluding": "2.10"}
        config = {"operator": "AND", "negate": True, "nodes": [{"cpeMatch": [criterion]}]}
        item["cve"]["configurations"] = [config]
        parsed = parse_cve(item)
        self.assertEqual(json.loads(parsed["app_config"][0]["original_config"]), config)
        self.assertEqual(parsed["criterion"][0]["vulnerable_flag"], "N")
        self.assertEqual(parsed["criterion"][0]["version_end_excl"], "2.10")
        self.assertEqual(parsed["criterion"][0]["criterion_path"], "/nodes/0/cpeMatch/0")

    def test_escaped_components_and_ambiguous_keys(self):
        self.assertEqual(product_key(split_cpe(r"cpe:2.3:a:vendor:the\:tool:*:*:*:*:*:*:*:*")),
                         ("a", "vendor", r"the\:tool"))
        self.assertEqual(product_key(split_cpe("cpe:2.3:a:*:tool:*:*:*:*:*:*:*:*")),
                         (None, None, None))
        with self.assertRaises(ValueError):
            split_cpe("cpe:2.3:a:not-enough")


class ClientTests(TestCase):
    def test_retry_pagination_and_archive(self):
        indices, delays, archived = [], [], []

        def open_page(request, timeout):
            self.assertEqual(timeout, 30)
            start = int(parse_qs(urlsplit(request.full_url).query)["startIndex"][0])
            indices.append(start)
            if len(indices) == 1:
                raise HTTPError(request.full_url, 429, "Slow down", {"Retry-After": "10"}, None)
            return BytesIO(json.dumps({
                "startIndex": start, "totalResults": 2, "vulnerabilities": [example()],
            }).encode())

        client = NvdClient(opener=open_page, sleep=delays.append)
        pages = list(client.pages("cves", "vulnerabilities", {}, page_size=1, max_records=4,
                                  archive=lambda index, raw: archived.append((index, json.loads(raw)))))
        self.assertEqual(indices, [0, 0, 1])
        self.assertEqual(delays, [10, 6])
        self.assertEqual([index for index, _ in pages], [0, 1])
        self.assertEqual([index for index, _ in archived], [0, 1])

    def test_empty_partial_page_fails_and_is_retained(self):
        client = NvdClient(opener=lambda *a, **k: BytesIO(
            b'{"startIndex":0,"totalResults":1,"vulnerabilities":[]}'
        ))
        archive = []
        with self.assertRaisesRegex(ValueError, "pagination"):
            list(client.pages("cves", "vulnerabilities", {}, page_size=1, max_records=2,
                              archive=lambda _, raw: archive.append(raw)))
        self.assertEqual(len(archive), 1)

    def test_batch_export_and_replay_validation(self):
        items = [example(), example(), {"cve": {"id": "invalid"}}]
        raw = json.dumps({"startIndex": 0, "totalResults": len(items), "vulnerabilities": items}).encode()
        client = NvdClient(opener=lambda *a, **k: BytesIO(raw))
        with TemporaryDirectory() as temp:
            batch = Path(temp) / "batch"
            manifest = write_batch(client, batch, {}, page_size=3)
            self.assertEqual((manifest["retrieved"], manifest["accepted"], manifest["rejected"]), (3, 1, 2))
            self.assertEqual((batch / "raw" / "cves-00000000.json").read_bytes(), raw)
            _, rows = read_batch(batch)
            self.assertEqual(rows["vulnerability"][0]["description"],
                             items[0]["cve"]["descriptions"][0]["value"])
            self.assertEqual(len(rows["vulnerability"][0]["revision_hash"]), 64)
            self.assertEqual(rows["vulnerability"][0]["cvss_score"], "")
            self.assertEqual({row["external_id"] for row in rows["reject"]}, {"invalid", "CVE-9999-0001"})
            with (batch / "vulnerability.csv").open("a", newline="", encoding="utf-8") as target:
                csv.writer(target).writerow(["tampered"])
            with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
                read_batch(batch)

    def test_batch_rejects_rehashed_csv_with_wrong_source_locator(self):
        items = [example(), {"cve": {"id": "invalid"}}]
        raw = json.dumps({"startIndex": 0, "totalResults": len(items), "vulnerabilities": items}).encode()
        client = NvdClient(opener=lambda *a, **k: BytesIO(raw))
        with TemporaryDirectory() as temp:
            batch = Path(temp) / "batch"
            manifest = write_batch(client, batch, {}, page_size=2)
            filename = "vulnerability.csv"
            path = batch / filename
            original = path.read_bytes()
            for locator, message in (
                (b"vulnerabilities/1", "row locators do not reconcile"),
                (b"vulnerabilities/2", "Invalid row"),
            ):
                with self.subTest(locator=locator):
                    updated = original.replace(b"vulnerabilities/0", locator)
                    path.write_bytes(updated)
                    manifest["files"][filename] = sha256(updated).hexdigest()
                    (batch / "manifest.json").write_text(json.dumps(manifest))
                    with self.assertRaisesRegex(ValueError, message):
                        read_batch(batch)

    def test_legacy_ftp_reference_is_preserved_as_metadata(self):
        item = example()
        url = "ftp://archive.example.invalid/vendor-advisory.txt"
        item["cve"]["references"] = [{"url": url, "source": "test"}]
        self.assertEqual(parse_cve(item)["reference"][0]["reference_url"], url)

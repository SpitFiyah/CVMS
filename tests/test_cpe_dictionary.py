from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from urllib.parse import parse_qs, urlsplit

from etl.cpe_dictionary import reconcile
from etl.nvd_client import NvdClient


NAME = "cpe:2.3:a:test_vendor:test_product:1.0:*:*:*:*:*:*:*"


class DictionaryTests(TestCase):
    def test_archive_and_keep_exact_matches_with_deprecation(self):
        products = [
            {"cpe": {"cpeName": NAME.replace(":1.0:", ":2.0:"), "cpeNameId": "different", "deprecated": False}},
            {"cpe": {"cpeName": NAME, "cpeNameId": "exact", "deprecated": True}},
        ]
        raw = json.dumps({"startIndex": 0, "totalResults": 2, "products": products}).encode()

        def opener(request, timeout):
            parsed = urlsplit(request.full_url)
            self.assertEqual(parsed.path, "/rest/json/cpes/2.0")
            self.assertEqual(parse_qs(parsed.query)["cpeMatchString"], [NAME])
            return BytesIO(raw)

        with TemporaryDirectory() as temp:
            output = Path(temp) / "dictionary"
            result = reconcile(NvdClient(opener=opener), output, [NAME, NAME])
            self.assertEqual(len(result["checks"]), 1)
            check = result["checks"][0]
            self.assertEqual(check["exact_matches"], [{"cpe_name_id": "exact", "deprecated": True}])
            self.assertTrue(check["complete"])
            page = check["raw_pages"][0]
            self.assertEqual((output / page["file"]).read_bytes(), raw)
            self.assertEqual(page["sha256"], sha256(raw).hexdigest())
            self.assertEqual(json.loads((output / "report.json").read_text()), result)

    def test_capped_search_marks_incomplete(self):
        raw = b'{"startIndex":0,"totalResults":3,"products":[{"cpe":{"cpeName":"cpe:2.3:a:test_vendor:test_product:2.0:*:*:*:*:*:*:*"}}]}'
        with TemporaryDirectory() as temp:
            result = reconcile(NvdClient(opener=lambda *a, **kw: BytesIO(raw)),
                               Path(temp) / "dictionary", [NAME], max_records=1)
        check = result["checks"][0]
        self.assertFalse(check["complete"])
        self.assertEqual(check["reviewed"], 1)
        self.assertEqual(check["exact_matches"], [])

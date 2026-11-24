"""Retrieve bounded NVD API pages and retain their original response bytes."""

import json
import os
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


ENDPOINTS = {
    "cves": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "cpes": "https://services.nvd.nist.gov/rest/json/cpes/2.0",
    "cpematch": "https://services.nvd.nist.gov/rest/json/cpematch/2.0",
}
RETRYABLE = {429, 500, 502, 503, 504}


class NvdClient:
    def __init__(self, *, api_key=None, opener=urlopen, sleep=time.sleep, attempts=4):
        if attempts < 1:
            raise ValueError("attempts must be positive")
        self.api_key = api_key
        self.opener = opener
        self.sleep = sleep
        self.attempts = attempts
        self.interval = 0.7 if api_key else 6
        self.requested = False

    @classmethod
    def from_environment(cls):
        return cls(api_key=os.environ.get("NVD_API_KEY"))

    def fetch(self, resource, filters):
        request = Request(
            f"{ENDPOINTS[resource]}?{urlencode(filters)}",
            headers={"Accept": "application/json", "User-Agent": "CVMS-academic"},
        )
        if self.api_key:
            request.add_header("apiKey", self.api_key)

        delay = 0
        for attempt in range(self.attempts):
            if self.requested:
                self.sleep(max(self.interval, delay))
            self.requested = True
            try:
                with self.opener(request, timeout=30) as response:
                    return response.read()
            except HTTPError as error:
                error.close()
                if error.code not in RETRYABLE or attempt == self.attempts - 1:
                    raise
                retry_after = error.headers.get("Retry-After", "")
                delay = max(min(2 ** attempt, 60), min(int(retry_after), 120) if retry_after.isdecimal() else 0)
            except (URLError, TimeoutError):
                if attempt == self.attempts - 1:
                    raise
                delay = min(2 ** attempt, 60)
        raise AssertionError("unreachable")

    def pages(self, resource, items_key, filters, *, page_size, max_records, archive):
        if not 1 <= page_size <= 100 or max_records < 1:
            raise ValueError("page_size must be 1–100 and max_records must be positive")
        start = 0
        while start < max_records:
            size = min(max_records - start, page_size)
            raw = self.fetch(resource, {**filters, "startIndex": start, "resultsPerPage": size})
            archive(start, raw)
            response = json.loads(raw)
            actual_start = response["startIndex"]
            total = response["totalResults"]
            items = response[items_key]
            if (
                type(actual_start) is not int or actual_start != start
                or type(total) is not int or total < 0
                or not isinstance(items, list) or len(items) > size
                or (items and start + len(items) > total)
                or (not items and start < total)
            ):
                raise ValueError("Inconsistent NVD pagination metadata")
            yield start, items
            start += len(items)
            if not items or start >= total:
                return

"""Verify an archived CVMS batch and load it into Oracle staging."""

import argparse
import csv
from datetime import datetime
from decimal import Decimal
from hashlib import sha256
from io import StringIO
import json
import os
from pathlib import Path

from .normalizer import FIELDS
from .nvd_client import ENDPOINTS


def checked_file(batch, name, expected):
    if not isinstance(name, str) or Path(name).is_absolute() or ".." in Path(name).parts:
        raise ValueError("Invalid manifest path")
    data = (batch / name).read_bytes()
    if sha256(data).hexdigest() != expected:
        raise ValueError(f"Checksum mismatch for {name}")
    return data


def read_batch(batch):
    manifest = json.loads((batch / "manifest.json").read_text(encoding="utf-8"))
    if manifest["format_version"] != 1 or manifest["source_url"] != ENDPOINTS["cves"]:
        raise ValueError("Unsupported batch")
    if not manifest["raw_pages"]:
        raise ValueError("Batch has no raw pages")
    raw_names = set()
    for page in manifest["raw_pages"]:
        filename = f"cves-{page['start_index']:08d}.json"
        if page["file"] != f"raw/{filename}" or filename in raw_names:
            raise ValueError("Invalid or duplicate raw page path")
        checked_file(batch, page["file"], page["sha256"])
        raw_names.add(filename)
    rows = {}
    for table, fields in FIELDS.items():
        filename = f"{table}.csv"
        data = checked_file(batch, filename, manifest["files"][filename])
        reader = csv.DictReader(StringIO(data.decode("utf-8"), newline=""))
        if reader.fieldnames != ["row_locator", *fields]:
            raise ValueError(f"Unexpected header in {filename}")
        rows[table] = list(reader)
        for row in rows[table]:
            if None in row or None in row.values() or row["row_locator"].split("#", 1)[0] not in raw_names:
                raise ValueError(f"Invalid row in {filename}")
    if (
        manifest["accepted"] != len(rows["vulnerability"])
        or manifest["rejected"] != len(rows["reject"])
        or manifest["retrieved"] != manifest["accepted"] + manifest["rejected"]
    ):
        raise ValueError("Manifest counts do not reconcile")
    return manifest, rows


def stage(cursor, driver, run_id, rows):
    field_types = {
        "description": driver.DB_TYPE_CLOB,
        "original_config": driver.DB_TYPE_CLOB,
        "published_date": driver.DB_TYPE_TIMESTAMP,
        "last_modified_date": driver.DB_TYPE_TIMESTAMP,
        "cvss_score": driver.DB_TYPE_NUMBER,
        "config_ordinal": driver.DB_TYPE_NUMBER,
    }
    conversions = {
        "published_date": datetime.fromisoformat,
        "last_modified_date": datetime.fromisoformat,
        "cvss_score": Decimal,
        "config_ordinal": int,
    }
    for table, fields in FIELDS.items():
        if not rows[table]:
            continue
        target = "import_reject" if table == "reject" else f"stg_{table}"
        columns = ("run_id", "row_locator", *fields)
        parameters = []
        for row in rows[table]:
            parameters.append({
                "run_id": run_id,
                **{
                    field: conversions.get(field, str)(value) if value else None
                    for field, value in row.items()
                },
            })
        cursor.setinputsizes(**{name: field_types[name] for name in columns if name in field_types})
        cursor.executemany(
            f"INSERT INTO {target} ({', '.join(columns)}) VALUES ({', '.join(':' + col for col in columns)})",
            parameters,
        )


def import_batch(connection, driver, batch, manifest, rows):
    with connection.cursor() as cursor:
        cursor.execute("SELECT source_id FROM data_source WHERE source_name = 'NVD'")
        source = cursor.fetchone()
        if source is None:
            raise ValueError("Seed the NVD data source before importing")
        run_var = cursor.var(driver.DB_TYPE_NUMBER)
        cursor.execute(
            """INSERT INTO import_run (source_id, dataset_version, manifest_locator, retrieved_count)
               VALUES (:source_id, 'NVD API 2.0', :locator, :retrieved)
               RETURNING run_id INTO :run_id""",
            source_id=source[0], locator=str(batch.resolve() / "manifest.json"),
            retrieved=manifest["retrieved"], run_id=run_var,
        )
        run_id = int(run_var.getvalue()[0])
        connection.commit()
        try:
            stage(cursor, driver, run_id, rows)
            cursor.callproc("publish_nvd_run", [run_id])
            cursor.execute(
                """SELECT retrieved_count, accepted_count, rejected_count, applied_count
                   FROM import_run WHERE run_id = :run_id""",
                run_id=run_id,
            )
            counts = cursor.fetchone()
            connection.commit()
        except Exception as error:
            connection.rollback()
            cursor.execute(
                """UPDATE import_run SET status = 'FAILED', ended_at = SYS_EXTRACT_UTC(SYSTIMESTAMP),
                   error_summary = :summary WHERE run_id = :run_id AND status = 'RUNNING'""",
                summary=str(error)[:1000], run_id=run_id,
            )
            connection.commit()
            raise
    return dict(zip(("run_id", "retrieved", "accepted", "rejected", "applied"), (run_id, *counts)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("batch", type=Path)
    args = parser.parse_args()
    manifest, rows = read_batch(args.batch)
    import oracledb

    oracledb.init_oracle_client()
    with oracledb.connect(user=os.environ["ORACLE_USER"], password=os.environ["ORACLE_PASSWORD"],
                          dsn=os.environ["ORACLE_DSN"]) as connection:
        print(json.dumps(import_batch(connection, oracledb, args.batch, manifest, rows)))


if __name__ == "__main__":
    main()

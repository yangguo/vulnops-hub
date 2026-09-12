#!/usr/bin/env python3
"""Smoke helper: put/get SBOM bytes and verify SHA-256 against object metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

from vulnops.config import get_settings
from vulnops.object_storage.object_store import (
    get_object_bytes,
    is_object_storage_configured,
    persist_sbom_raw_bytes,
    verify_sbom_object_digest,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--organization-id",
        default="org-smoke",
        help="Organization id used in the SBOM object key",
    )
    parser.add_argument(
        "--payload",
        default='{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}',
        help="Raw JSON document to store",
    )
    args = parser.parse_args(argv)

    settings = get_settings()
    if not is_object_storage_configured(settings):
        print(
            "OBJECT_STORAGE_ENDPOINT, ACCESS_KEY, and SECRET_KEY must be set",
            file=sys.stderr,
        )
        return 2

    raw = args.payload.encode()
    digest = hashlib.sha256(raw).hexdigest()
    uri = persist_sbom_raw_bytes(
        raw,
        settings.object_storage_bucket,
        args.organization_id,
        digest,
        settings,
    )
    fetched = get_object_bytes(uri, settings)
    ok = verify_sbom_object_digest(uri, digest, settings)
    print(
        json.dumps(
            {
                "object_uri": uri,
                "content_sha256": digest,
                "bytes_len": len(fetched),
                "digest_ok": ok,
            },
            indent=2,
        )
    )
    return 0 if ok and fetched == raw else 1


if __name__ == "__main__":
    raise SystemExit(main())

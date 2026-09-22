"""Offline cross-project smoke check; both source packages must be importable.

Run with PYTHONPATH pointing to the LureBench and LureScope checkouts. Generates
only a tiny synthetic checkpoint in a temporary directory, with no model loads.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from lurescope.checkpoint import verify_checkpoint

from lurebench.checkpoint import INDEX_NAME, inspect_checkpoint


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="checkpoint-interop-") as temporary:
        root = Path(temporary)
        directory = root / "checkpoint"
        directory.mkdir()
        header = json.dumps({"synthetic": {
            "dtype": "U8", "shape": [4], "data_offsets": [0, 4],
        }}, separators=(",", ":")).encode()
        shard = directory / "weights.safetensors"
        original = len(header).to_bytes(8, "little") + header + b"\x00\x01\x02\x03"
        shard.write_bytes(original)
        (directory / INDEX_NAME).write_text(json.dumps({
            "metadata": {"total_size": 4},
            "weight_map": {"synthetic": shard.name},
        }))
        report = root / "report.json"
        payload = json.dumps(inspect_checkpoint(directory), sort_keys=True).encode()
        report.write_bytes(payload)
        # Local fixture trust anchor only, not a production trust bootstrap.
        approved = hashlib.sha256(payload).hexdigest()
        result = verify_checkpoint(directory, report, expected_report_sha256=approved)
        assert result["summary"]["status"] == "byte_match"
        probes = 0
        for replace_report in (False, True):
            shard.write_bytes(original[:-1] + b"\x04")
            if replace_report:
                report.write_text(json.dumps(inspect_checkpoint(directory), sort_keys=True))
            try:
                verify_checkpoint(directory, report, expected_report_sha256=approved)
            except ValueError:
                probes += 1
            else:
                raise AssertionError("changed checkpoint/report must not pass the original pin")
        assert probes == 2
        print("CHECKPOINT INTEROP: PASS — byte match and 2 substitution probes")


if __name__ == "__main__":
    main()

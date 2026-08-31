"""Project one synthetic, already-verified CAEP event without network access."""

from __future__ import annotations

import json

from lurebench.revocation import CAEP_SESSION_REVOKED
from lurebench.revocation_adapters import project_verified_caep_event


def main() -> None:
    decoded_verified_set = {
        "iss": "https://identity.example.invalid",
        "jti": "synthetic-event-1",
        "iat": 2_000_000_010,
        "aud": "https://receiver.example.invalid/caep",
        "sub_id": {
            "format": "complex",
            "user": {"format": "iss_sub", "iss": "synthetic-idp", "sub": "user-123"},
            "tenant": {"format": "opaque", "id": "tenant-456"},
        },
        "events": {
            CAEP_SESSION_REVOKED: {
                "event_timestamp": 2_000_000_010,
                "initiating_entity": "policy",
            }
        },
    }
    projected = project_verified_caep_event(
        decoded_verified_set,
        verification={
            "signature_verified": True,
            "issuer_verified": True,
            "audience_verified": True,
            "time_verified": True,
            "delivery_method": "push",
        },
        expected_issuer="https://identity.example.invalid",
        expected_audience="https://receiver.example.invalid/caep",
        subject_hmac_key=b"synthetic-campaign-key-32-bytes!!",
        sequence=1,
        epoch_seconds=2_000_000_000,
    )
    print(json.dumps(projected, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

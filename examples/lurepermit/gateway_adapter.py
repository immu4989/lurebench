"""Minimal side-effect-free LurePermit engine adapter.

Replace only ``policy_decision`` with an adapter to an organization's decision
logic. The adapter must evaluate metadata and must never execute the requested
operation. Scenario expectations are retained by the LureRange harness.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from lurebench.permit import reference_permit_engine, run_range_evaluation


def policy_decision(
    request: Mapping[str, Any], permit: Mapping[str, Any]
) -> Mapping[str, Any]:
    """Return one policy decision; no requested action is performed."""

    return reference_permit_engine(request, permit)


if __name__ == "__main__":
    report = run_range_evaluation(
        engine=policy_decision,
        engine_id="example-policy-gateway",
        engine_version="1.0.0",
    )
    print(json.dumps(report["summary"], indent=2, sort_keys=True))

"""An intentionally failing gateway adapter for learning the runner contract.

It blocks everything and makes no network calls or real changes. A successful
submission export is not a passing score. Replace this adapter with your own
test gateway integration; do not use this example as a policy enforcement engine.
"""

from __future__ import annotations

from typing import Any, Mapping


class AlwaysBlockGateway:
    def __init__(self) -> None:
        self.active = False
        self.next_sequence = 1

    def begin(self, plan: Mapping[str, Any], execution: Mapping[str, Any]) -> None:
        if self.active:
            raise ValueError("session already active")
        self.active = True
        self.next_sequence = 1

    def decide(self, case: Mapping[str, Any]) -> Mapping[str, str]:
        if not self.active or case["sequence"] != self.next_sequence:
            raise ValueError("ordered session required")
        self.next_sequence += 1
        return {"decision": "block", "reason_code": "policy_unknown"}

    def close(self) -> None:
        self.active = False


def create_adapter() -> AlwaysBlockGateway:
    return AlwaysBlockGateway()

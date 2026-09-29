"""Exercise policy producer/consumer round trips using synthetic observations only."""

import copy
import hashlib
import json
import tempfile
from pathlib import Path

from lurescope.policy import load_policy

from lurebench.calibration import DecisionPolicy, build_policy


def main():
    with tempfile.TemporaryDirectory(prefix="lure-policy-interop-") as directory:
        path = Path(directory) / "policy.json"
        for name, objective in [("synthetic", "max_mcc"), ("d" * 256, "target_fpr"),
                                ("synthetic", "risk_controlled_fpr")]:
            policy, _ = build_policy(name, "fraud", [str(i) for i in range(401)],
                                     [0] * 400 + [1], [.1] * 400 + [.9],
                                     objective=objective, target_fpr=.01,
                                     threshold_grid_size=101)
            policy.save(str(path))
            pin = hashlib.sha256(path.read_bytes()).hexdigest()
            producer = DecisionPolicy.load(str(path), expected_sha256=pin)
            consumer = load_policy(str(path), expected_sha256=pin)
            assert producer.policy_id == consumer.policy_id
            assert producer.threshold == consumer.threshold
            assert producer.validation_sha256 == consumer.validation_sha256
            for field, bad in [("threshold", True), ("validation_records", False),
                               ("detector", "\ud800"), ("objective", "unknown")]:
                payload = copy.deepcopy(policy.as_dict())
                payload[field] = bad
                path.write_text(json.dumps(payload))
                for loader in (DecisionPolicy.load, load_policy):
                    try:
                        loader(str(path))
                    except ValueError:
                        pass
                    else:
                        raise AssertionError(f"invalid policy accepted: {field}")
    print("policy interop: three objective profiles and shared rejection probes passed")


if __name__ == "__main__":
    main()

"""Serialization tolerance must never increase a statistical acceptance limit."""

import json
from dataclasses import replace

import pytest

from lurebench.calibration import (
    DecisionPolicy,
    binomial_cdf,
    build_policy,
    clopper_pearson_upper,
    select_risk_controlled_threshold,
)


@pytest.mark.parametrize("case", ["recomputed", "understated", "reported_p", "reported_upper"])
def test_no_tolerance_budget_at_acceptance_boundary(tmp_path, case):
    policy, _ = build_policy("tfidf-logreg", "fraud", [str(i) for i in range(401)],
        [0] * 400 + [1], [.1] * 400 + [.9], "risk_controlled_fpr", .01)
    bound = clopper_pearson_upper(0, 400, .95)
    target = bound - 1e-14 if case in {"recomputed", "understated"} else bound + 1e-14
    p_value = binomial_cdf(0, 400, target)
    control = replace(policy.risk_control, upper_confidence_bound=bound,
                      hypothesis_p_value=p_value)
    if case == "understated":
        control = replace(control, upper_confidence_bound=target, hypothesis_p_value=1-.95)
    elif case == "reported_p":
        control = replace(control, hypothesis_p_value=1-.95+1e-14)
    elif case == "reported_upper":
        control = replace(control, upper_confidence_bound=target+1e-14)
    policy = replace(policy, target_fpr=target, risk_control=control)
    # Write raw hostile evidence so publication validation cannot mask the loader.
    path = tmp_path / "boundary-policy.json"
    path.write_text(json.dumps(policy.as_dict()))
    with pytest.raises(ValueError):
        DecisionPolicy.load(str(path))
    destination = tmp_path / "preserved.json"
    destination.write_text("previous approved bytes")
    with pytest.raises(ValueError):
        policy.save(str(destination))
    assert destination.read_text() == "previous approved bytes"


def test_selector_never_returns_an_uncertified_floating_boundary():
    # At this confidence, 1-confidence rounds to 1. A rounded CDF can admit
    # one false positive, but the independently computed bound cannot certify it.
    with pytest.raises(ValueError):
        select_risk_controlled_threshold([0, 0, 1], [.1, .2, .9], 1e-30, confidence=1e-20)

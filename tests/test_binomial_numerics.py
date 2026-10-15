"""Independent tail oracles and bounded-memory recurrence regressions."""

import math
import tracemalloc
from decimal import Decimal, localcontext

import pytest

from lurebench.calibration import binomial_cdf, clopper_pearson_upper


@pytest.mark.parametrize("events,trials", [(40000, 100000), (450000, 1000000)])
def test_underflow_does_not_leave_a_subnormal_plateau(events, trials):
    # The lower tail is below the smallest binary64 number (Chernoff exponent
    # already below -5000 in the second case), not a sum of rounded-up minima.
    assert binomial_cdf(events, trials, .5) == 0.0


def test_cdf_does_not_retain_the_distribution_in_memory():
    tracemalloc.start()
    try:
        result = binomial_cdf(100000, 200000, .5)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert .5 < result < .51
    assert peak < 512 * 1024


@pytest.mark.parametrize("events,trials,p", [
    (0, 1000, .5), (1, 1000, .5), (4, 1000, .5),
    (0, 100, .001), (1, 100, .001), (3, 100, .01),
    (0, 10, 1e-100), (2, 10, .9), (9, 10, .999999),
    (25, 50, .5), (3, 20, .3), (19, 20, .8),
])
def test_tail_matches_independent_decimal_sum(events, trials, p):
    with localcontext() as context:
        context.prec = 100
        probability = Decimal.from_float(p)
        complement = 1 - probability
        expected = float(sum(Decimal(math.comb(trials, k)) * probability ** k
                             * complement ** (trials - k) for k in range(events + 1)))
    assert binomial_cdf(events, trials, p) == pytest.approx(expected, rel=2e-13, abs=0)


@pytest.mark.parametrize("events,trials,p", [
    (100, 100000, .001), (1000, 100000, .01), (50000, 100000, .5),
    (49000, 100000, .5), (99000, 100000, .99),
    (499000, 1000000, .5), (500000, 1000000, .5),
    (20, 1000000, .00001), (1, 10000, .1),
])
def test_large_tail_matches_scipy_oracle(events, trials, p):
    stats = pytest.importorskip("scipy.stats")
    expected = float(stats.binom.cdf(events, trials, p))
    assert binomial_cdf(events, trials, p) == pytest.approx(expected, rel=2e-11, abs=1e-323)


@pytest.mark.parametrize("trials,confidence", [
    (1, .95), (400, .95), (10000000, .99), (400, 1e-20),
    (1, math.nextafter(1., 0.)), (10, math.nextafter(0., 1.)),
])
def test_zero_event_bound_matches_stable_closed_form(trials, confidence):
    expected = -math.expm1(math.log1p(-confidence) / trials)
    bound = clopper_pearson_upper(0, trials, confidence)
    assert bound >= expected
    assert bound <= math.nextafter(expected, math.inf)


def test_zero_event_bound_never_enumerates_a_distribution(monkeypatch):
    import lurebench.calibration as calibration

    monkeypatch.setattr(calibration, "binomial_cdf", lambda *a: pytest.fail("CDF evaluated"))
    assert 0 < calibration.clopper_pearson_upper(0, 10000000, .95) < .000001


@pytest.mark.parametrize("events,trials,confidence", [
    (1, 1000, .95), (10, 1000, .99), (500, 1000, .95),
    (999, 1000, .95), (100, 10000, .999), (1, 100000, .95),
    (50, 100000, .5), (1, 100, math.nextafter(1., 0.)),
])
def test_nonzero_event_bounds_match_independent_beta_quantile(events, trials, confidence):
    stats = pytest.importorskip("scipy.stats")
    expected = float(stats.beta.ppf(confidence, events + 1, trials - events))
    assert clopper_pearson_upper(events, trials, confidence) == pytest.approx(expected, rel=2e-11)

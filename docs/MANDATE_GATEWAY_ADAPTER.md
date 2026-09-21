# Connect a test gateway to LureMandate

Availability: these commands are currently unreleased. Use the current source
checkout or a wheel built from it; the published 0.11.0 release predates them.

The adapter SDK collects a complete submission from your gateway in one ordered
session. It works with all existing LureMandate challenges, including shared-state
transitions. You do not need to construct submission JSON or calculate its bindings.

## Try the offline example

Run these commands from the source checkout root. For a wheel-only installation,
`lurebench.mandate_selftest.reference_corpus_root()` locates the installed
reference directory; use its `luremandate-transitions-v1/challenge.json` file.

```sh
lurebench mandate-run-gateway \
  conformance/luremandate-transitions-v1/challenge.json \
  --adapter lurebench.mandate_gateway_example:create_adapter \
  --submission-id example-1 \
  --engine-id example-always-block --engine-version 1.0.0 \
  --out example-submission.json

lurebench mandate-score \
  --challenge conformance/luremandate-transitions-v1/challenge.json \
  --submission example-submission.json \
  --out example-score.json
```

The first command exits 0 when it exports all answers. The example deliberately
blocks everything, so scoring exits 1. It makes no network calls or real changes.
Malformed input, adapter failure, or an existing output path makes the runner
exit 2 without exporting a partial submission.

## Implement your adapter

Make a Python module importable in the environment where LureBench runs. Export
a zero-argument factory that returns an object with three synchronous methods:

```python
class GatewayAdapter:
    def begin(self, plan, execution):
        # Create an isolated test session and configure its policy.
        # Use execution["run_id"] and the supplied logical timestamps.
        self.session = my_test_gateway.begin(plan=plan, execution=execution)

    def decide(self, case):
        # Keep this session across all cases; do not reset it here.
        response = self.session.decide(case["transaction"])
        return {
            "decision": response.decision,       # "allow" or "block"
            "reason_code": response.reason_code,
        }

    def close(self):
        # Must tolerate begin() failing before session creation completes.
        session = getattr(self, "session", None)
        if session is not None:
            session.close()

def create_adapter():
    return GatewayAdapter()
```

`my_test_gateway` represents your integration code. Configure explicit transport
timeouts there. The SDK is synchronous and does not interrupt hung Python calls.
Use `--adapter your_package.your_module:create_adapter` with an explicit engine
ID and version. `--engine-artifact-sha256` records your declared build digest;
the runner does not attest to what engine executed remotely.

The runner passes copies of the plan, execution metadata, and each answer-free
case. It invokes `begin` once, calls `decide` in case order, and invokes `close`
once even after a session failure. Responses must contain exactly `decision`
and `reason_code`, using the contract's reason vocabulary. Oracle answers are
never passed to the adapter. The factory should create a lightweight object;
allocate external session resources in `begin` and release them in `close`.
The file runner validates the challenge, output location, and submission metadata
before importing the adapter factory. Invalid input therefore cannot start a
session through that factory. An existing output is never overwritten.
`begin` and `close` must return `None` and raise an exception for failure.
Async functions, async callable objects, generators, and hidden coroutine
returns are rejected; lifecycle return values are not silently ignored.

The runner does not retry decisions. Your transport must also avoid automatic
retries unless the gateway provides a tested idempotency contract. An interrupted
campaign may have partially exercised the test system even though no submission
was written; start a fresh isolated session before rerunning it.

This interface executes trusted Python code with the caller's permissions.
Target a disposable test environment and keep production mutation endpoints out
of the adapter. The SDK supplies no sandbox or transport authentication. CLI
errors omit exception text because SDK/network errors may contain credentials;
use a controlled local debugger for adapter diagnostics.

## Verify collected evidence independently

After scoring, pass the challenge, submission, and score to LureScope:

```sh
lurescope mandate verify-conformance challenge.json submission.json score.json \
  --out verification.json
```

The verifier checks score semantics. Gateway identity authentication remains the
separate `sign-conformance` / `authenticate-conformance` workflow.

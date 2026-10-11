# Dependency verification on 10 October 2026

Unreleased changes based on `a501504cec002ffbaff810742e14e2dd002ed543` update the
optional urllib3 lock from 2.7.0 to 2.8.0 and add a uv resolution floor. At
verification time, the changes were local and uncommitted; the default branch,
published packages, and remote security alerts were unchanged.

The upstream advisories identify 2.8.0 as the patched release for
[unbounded chunk-size-line buffering](https://github.com/advisories/GHSA-vxq7-64xx-v4gw)
and the [chunked Deflate loop](https://github.com/advisories/GHSA-gh4c-6fx4-qh6g).
Only urllib3 changed version during lock resolution. The existing HTTPX2 floor
remains, and the core harness still has no required third-party dependencies.

## Results

| Check | Result |
| --- | --- |
| Offline uv lock consistency | Passed across 120 resolved packages |
| HTTPX2 and urllib3 floor tests | Both passed; all matching lock entries checked |
| Full suite with temporary urllib3 2.8.0 ahead of the development environment | 1,438 passed, 39 skipped, 9 warnings |
| Ruff and Git whitespace checks | Passed |

The compatibility run verified the imported version and temporary package path
before running tests. It did not replace packages in the existing development
environment. Thirty-six skips concern the optional Safetensors reference reader,
two require unavailable full corpus shards, and one concerns missing schemas in
the installed STIX validator. Existing solver-option and joblib/NumPy warnings
remain. Passing these tests is not a complete runtime reachability assessment.

The uv floor does not constrain independently resolved pip environments or upgrade
existing installations. Consumers need to update their own affected HTTP stack.
The optional Accelerate advisory still lists no patched release and remains
unresolved; see [dependency security](DEPENDENCY_SECURITY.md). No alerts were
dismissed, no provider endpoints were called, and no models were downloaded.

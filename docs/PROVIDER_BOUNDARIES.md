# Provider transport boundary (unreleased)

The dependency-free compatible-provider client has a deliberately bounded
text-completion profile. These controls apply to this client, not every optional
third-party SDK, HTTP library, provider, or deployment gateway.

- HTTPS is required by default. URL userinfo, query strings, fragments,
  whitespace/control characters, backslashes, and invalid ports are rejected.
  Local plaintext development requires explicit `allow_insecure_http=True`;
  that option can expose credentials and content if used on an untrusted network.
- Authenticated requests do not follow HTTP redirects. Configure the reviewed
  canonical endpoint instead. Proxy settings supported by Python remain in
  effect; operators must trust their configured proxies and endpoint.
- Response bodies are read with an 8 MiB limit before strict JSON parsing.
  Error-body inspection reads at most 4 KiB and closes the response. Duplicate
  keys, non-finite numbers, and non-object responses are rejected.
- Raw provider error bodies are not inserted into raised configuration-error
  messages. Those messages retain status, configured model/endpoint identifiers,
  and static configuration guidance; treat those identifiers as potentially
  sensitive in operator logs.
- Extra parameters cannot override model, messages, temperature, max_tokens,
  stream, or n. They must be a finite JSON object no larger than 64 KiB and are
  copied so later mutations of the caller's input do not silently change them.
- Exactly one response choice is expected. Truncation, tool/function-call
  completion, and unknown finish reasons are incomplete evidence, not valid text
  classifications. A missing finish reason remains accepted for compatibility;
  a provider omitting it supplies no termination assurance.
- Retry counts and timing parameters are bounded and typed. Negative or
  non-finite numeric Retry-After values fall back to the configured delay. A
  bounded transport/JSON rejection is not automatically retried.

Limits: max_tokens 1–1,000,000; max_retries 0–10; timeout 0.001–600 seconds;
retry_base/max_delay 0–300 seconds; temperature 0–2. Timeout is the library's
blocking-operation timeout, **not an end-to-end deadline**. Retries may still
spend money if a provider processed a request before its response was lost.

This is not an egress allowlist, DNS/SSRF protection, provenance authentication,
or a guarantee of trustworthy responses. Model-selection errors use a bounded
textual heuristic; provider error conventions can differ. Use explicit budgets,
reviewed endpoints, least privilege, and [cache controls](CACHE_SAFETY.md).

In-memory transport tests exercise redirects and response handling without real
network requests or credentials. The opener behavior follows Python's documented
[urllib.request handler interface](https://docs.python.org/3/library/urllib.request.html#urllib.request.HTTPRedirectHandler).

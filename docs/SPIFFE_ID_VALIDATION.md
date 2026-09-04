# SPIFFE ID validation boundary

LurePermit Runtime and LureIdentity use the same bounded parser for workload
SPIFFE IDs and runtime-profile trust-domain allowlists. LureScope contains a
separate implementation and reruns the same adversarial vectors when it verifies
runtime and identity evidence.

The parser follows the stable [SPIFFE Identity and Verifiable Identity Document
specification](https://spiffe.io/docs/latest/spiffe-specs/spiffe-id/) for syntax:

- exact lowercase `spiffe://` canonical scheme;
- a nonempty, lowercase, ASCII trust domain of at most 255 bytes containing
  only `a-z`, `0-9`, `.`, `-`, or `_`;
- no user information, port, percent encoding, query, or fragment;
- an overall maximum of 2,048 ASCII bytes;
- case-sensitive path segments containing only letters, digits, `.`, `-`, and
  `_`; and
- no empty segment, `.` or `..` segment, or trailing slash.

The SPIFFE core format permits a root identity without a path. LureBench's
workload contracts deliberately require a non-root path because the field names
a workload, not a trust-domain authority. `parse_spiffe_id(...,
require_path=False)` remains available for validating a general SPIFFE ID.

The specification says the scheme is case-insensitive while separately
requiring a lowercase trust-domain host. LureBench requires the lowercase scheme
as a canonical serialization rule, preventing multiple byte strings from naming
the same identity in digests, policy comparisons, and evidence.

## What syntax validation does not establish

A valid string does not prove that:

- an X.509, JWT, or WIT SVID was issued or cryptographically valid;
- the presenting workload possesses the SVID's private key;
- a Workload API authenticated its local caller;
- an allowlisted trust domain is controlled by the expected organization;
- bundles are current, authentic, or correctly federated; or
- path segments have a mutually agreed authorization meaning.

Production integrations must obtain the SPIFFE ID from authenticated SVID
validation and separately govern trust bundles, federation, and path semantics.
Never accept an agent-supplied string as proof of workload identity.

The versioned [machine-readable conformance vectors](../conformance/spiffe-id-v1/vectors.json)
cover valid general/workload forms, malformed authority and URI components,
relative and empty path segments, canonical case, non-ASCII input, and boundary
lengths. They are governed by a public Draft 2020-12 schema and are packaged in
the wheel for independent implementations.

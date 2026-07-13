# The LureBench fraud-lure taxonomy & STIX 2.1 export

**Taxonomy version 1.0.** A shared vocabulary for AI-generated fraud lures, with curated
crosswalks to the frameworks a U.S. government or financial-sector analyst already uses,
and a one-command export to STIX 2.1 for threat-intel sharing.

## Why this exists

Detection is only half the job. The other half is *communicating* a detection in terms
another organization can act on. A bank, a fusion center, an ISAC, and an FBI field
office each have their own vocabulary; a fraud lure flagged in one has to be re-described
to travel to the next. LureBench already tags every record on three axes, so the cost of
turning that into an interoperable standard is low and the payoff — a detection that maps
cleanly onto FinCEN advisories, IC3 crime categories, and MITRE ATT&CK, and that exports
as STIX for machine ingestion — is high.

## Two honesty notes

1. **The crosswalks are curated by LureBench, not official designations.** Mapping the
   `bec` typology to MITRE `T1566.002` is our editorial judgment about how these
   vocabularies align. It is not endorsed by MITRE, FinCEN, or the FBI. Treat every
   external ID as a pointer to verify against the primary source.
2. **MITRE ATT&CK IDs here are precise and stable; the FinCEN/IC3 references name real
   programs but you should confirm the exact advisory** against the issuing agency, since
   advisory numbering changes and this document is a snapshot.

## The three axes

A lure is described by *what kind of fraud it is* (typology), *how it is delivered*
(channel), and *which social-engineering lever it pulls* (persuasion technique). The
tables below are generated from [`lurebench/taxonomy.py`](../lurebench/taxonomy.py), the
single source of truth, so they cannot drift from the code.

### Typologies

| Key | Label | Crosswalks |
|---|---|---|
| `phishing` | Phishing / credential theft | MITRE ATT&CK `T1566`; MITRE ATT&CK `T1598`; FBI/IC3 `phishing-spoofing`; FinCEN |
| `bec` | Business email compromise (BEC/EAC) | MITRE ATT&CK `T1566.002`; MITRE ATT&CK `T1656`; FBI/IC3 `bec-eac`; FinCEN |
| `romance` | Romance / confidence fraud | MITRE ATT&CK `T1656`; FBI/IC3 `confidence-romance` |
| `pig_butchering` | Pig-butchering / investment fraud | MITRE ATT&CK `T1656`; FBI/IC3 `investment`; FinCEN `FIN-2023-Alert006` |
| `benign` | Benign (non-fraud) | — (negative class; no fraud framework applies) |

### Channels → MITRE ATT&CK phishing sub-technique

| Key | Label | MITRE technique |
|---|---|---|
| `email` | Email | `T1566.001` (Attachment); `T1566.002` (Link) |
| `sms` | SMS / smishing | `T1566.003` (via Service) |
| `chat` | Chat / messaging app | `T1566.003` (via Service) |
| `social` | Social media | `T1566.003` (via Service) |
| `voice_transcript` | Voice / vishing (transcript) | `T1566.004` (Voice) |

### Persuasion techniques

Grounded in Cialdini's principles of influence, plus the coercive levers (fear, secrecy,
urgency) that show up operationally in fraud but sit outside the classic six.

| Key | Label |
|---|---|
| `authority` | Authority |
| `urgency` | Urgency / time pressure |
| `scarcity` | Scarcity |
| `social_proof` | Social proof |
| `reciprocity` | Reciprocity |
| `liking` | Liking / rapport |
| `commitment` | Commitment / consistency |
| `fear` | Fear / intimidation |
| `secrecy` | Secrecy / isolation |

## STIX 2.1 export

The taxonomy becomes STIX `attack-pattern` objects (each carrying its crosswalks as
`external_references`), and each lure becomes an `indicator` linked by `relationship`
objects to the patterns it exhibits. IDs are deterministic (name-based UUIDv5) and
timestamps are fixed, so the output is reproducible and diffable. Both the taxonomy-only
and full-dataset bundles pass the **official OASIS `stix2-validator`**.

```bash
# The taxonomy on its own — attack-patterns + crosswalks, no data
lurebench stix --taxonomy-only -o taxonomy.stix.json

# A dataset as a STIX bundle: identity + attack-patterns + one indicator per lure
lurebench stix -d data/full/core/test.jsonl -o lures.stix.json
```

Programmatically:

```python
from lurebench.stix import records_to_stix, taxonomy_to_stix, to_bundle
from lurebench.harness import load_jsonl

bundle = records_to_stix(load_jsonl("data/full/core/test.jsonl"))
taxonomy_bundle = to_bundle(taxonomy_to_stix())
```

Indicator patterns use the STIX `artifact:hashes.'SHA-256'` form over the (defanged) lure
text, so a bundle references content by hash without redistributing the lure itself.

## Extending it

Add a typology, channel, or persuasion lever in `lurebench/taxonomy.py` with its
crosswalks; `taxonomy.validate()` (run in the test suite) enforces that the taxonomy and
the dataset schema stay in sync. New terms flow into the STIX export automatically.

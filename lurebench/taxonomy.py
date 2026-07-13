"""A formal taxonomy of AI-generated fraud lures, with crosswalks to public frameworks.

LureBench already tags every record on three axes — **typology** (what kind of fraud),
**channel** (how it is delivered), and **persuasion technique** (the social-engineering
lever). This module turns that implicit vocabulary into an explicit, versioned standard
and maps each term to the frameworks a U.S. government or financial-sector analyst
already works in: FinCEN advisories, the FBI/IC3 crime categories, MITRE ATT&CK, and
(where it fits) the DISARM influence-operations framework. The point is
interoperability: a detection expressed in LureBench terms can be handed to a fusion
center, an ISAC, or a SAR narrative without re-inventing the vocabulary.

Two honesty notes, load-bearing:

- **The crosswalks are curated by LureBench, not official designations.** A mapping from
  the ``bec`` typology to MITRE T1566.002 is our editorial judgment about how these
  vocabularies line up; it is not endorsed by MITRE, FinCEN, or the FBI.
- **The targets are real and auditable.** Every FinCEN/IC3 reference carries its exact
  published identifier, title, date, and URL, verified against the issuing agency on the
  date in ``SOURCES_VERIFIED``. MITRE ATT&CK IDs are stable and versioned upstream. So the
  mapping is editorial, but nothing points at a document you can't open and check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .schema import CHANNELS, TYPOLOGIES

TAXONOMY_VERSION = "1.1"

# Date the FinCEN/FBI-IC3 references below were checked against the issuing agency's
# published documents. MITRE ATT&CK IDs are stable and versioned upstream.
SOURCES_VERIFIED = "2026-07-12"

DISCLAIMER = (
    "LureBench-curated crosswalk. The *mapping* from a LureBench term to an external "
    "framework entry is our editorial judgment, not an official designation by MITRE, "
    "FinCEN, or the FBI. The *targets*, however, are real, dated, published documents: "
    f"every FinCEN/IC3 reference was verified against the issuing agency on {SOURCES_VERIFIED}, "
    "and each carries its exact identifier and URL so you can audit the mapping yourself. "
    "The cross-cutting 'AI-generated' dimension is grounded in FBI/IC3 I-120324-PSA "
    "(Dec 3 2024) and FinCEN FIN-2024-Alert004 (Nov 13 2024)."
)


@dataclass(frozen=True)
class Crosswalk:
    """A pointer from a taxonomy term to an entry in an external framework."""

    framework: str          # e.g. "MITRE ATT&CK", "FBI/IC3", "FinCEN", "DISARM"
    ref_id: str             # e.g. "T1566.002" (may be empty when only a name is stable)
    name: str
    url: str = ""


@dataclass(frozen=True)
class TaxonomyEntry:
    key: str
    label: str
    description: str
    crosswalks: List[Crosswalk] = field(default_factory=list)


def _mitre(sub: str, name: str) -> Crosswalk:
    base = sub.split(".")[0]
    url = f"https://attack.mitre.org/techniques/{base}/"
    if "." in sub:
        url += f"{sub.split('.')[1]}/"
    return Crosswalk("MITRE ATT&CK", sub, name, url)


# --- Axis 1: fraud typology -------------------------------------------------------
TYPOLOGY_TAXONOMY: Dict[str, TaxonomyEntry] = {
    "phishing": TaxonomyEntry(
        "phishing", "Phishing / credential theft",
        "A message impersonating a trusted service to harvest credentials or push a "
        "malicious link or attachment.",
        [
            _mitre("T1566", "Phishing"),
            _mitre("T1598", "Phishing for Information"),
            Crosswalk("FBI/IC3", "phishing-spoofing", "Phishing/Spoofing (IC3 crime type)",
                      "https://www.ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf"),
            Crosswalk("FBI/IC3", "I-120324-PSA",
                      "Criminals Use Generative AI to Facilitate Financial Fraud (Dec 3 2024)",
                      "https://www.ic3.gov/PSA/2024/PSA241203"),
        ],
    ),
    "bec": TaxonomyEntry(
        "bec", "Business email compromise (BEC/EAC)",
        "Impersonation of an executive, vendor, or trusted party to redirect a payment "
        "or wire transfer.",
        [
            _mitre("T1566.002", "Spearphishing Link"),
            _mitre("T1656", "Impersonation"),
            Crosswalk("FBI/IC3", "bec-eac",
                      "Business Email Compromise / Email Account Compromise (IC3 crime type)",
                      "https://www.ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf"),
            Crosswalk("FinCEN", "FIN-2019-A005",
                      "Updated Advisory on Email Compromise Fraud Schemes (Jul 16 2019)",
                      "https://www.fincen.gov/resources/advisories/fincen-advisory-fin-2019-a005"),
        ],
    ),
    "romance": TaxonomyEntry(
        "romance", "Romance / confidence fraud",
        "A fabricated personal relationship built over time to extract money or "
        "financial access from the target.",
        [
            _mitre("T1656", "Impersonation"),
            Crosswalk("FBI/IC3", "confidence-romance", "Confidence Fraud / Romance (IC3 crime type)",
                      "https://www.ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf"),
        ],
    ),
    "pig_butchering": TaxonomyEntry(
        "pig_butchering", "Pig-butchering / investment fraud",
        "A long-con romance-plus-investment hybrid steering the target into a fraudulent "
        "(often crypto) investment platform.",
        [
            _mitre("T1656", "Impersonation"),
            Crosswalk("FBI/IC3", "investment",
                      "Investment fraud, incl. crypto-investment (IC3 crime type)",
                      "https://www.ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf"),
            Crosswalk("FinCEN", "FIN-2023-Alert005",
                      "Alert on the virtual-currency investment scam known as pig butchering "
                      "(Sep 8 2023)",
                      "https://www.fincen.gov/system/files/shared/FinCEN_Alert_Pig_Butchering_FINAL_508c.pdf"),
        ],
    ),
    "benign": TaxonomyEntry(
        "benign", "Benign (non-fraud)",
        "Legitimate message; the negative class for the fraud-detection task. No fraud "
        "framework applies.",
        [],
    ),
}

# --- Axis 2: delivery channel -> MITRE phishing sub-technique ----------------------
CHANNEL_TAXONOMY: Dict[str, TaxonomyEntry] = {
    "email": TaxonomyEntry("email", "Email", "Delivered as an email message.",
                           [_mitre("T1566.001", "Spearphishing Attachment"),
                            _mitre("T1566.002", "Spearphishing Link")]),
    "sms": TaxonomyEntry("sms", "SMS / smishing", "Delivered as a text message.",
                         [_mitre("T1566.003", "Spearphishing via Service")]),
    "chat": TaxonomyEntry("chat", "Chat / messaging app",
                          "Delivered over a messaging platform (WhatsApp, Telegram, etc.).",
                          [_mitre("T1566.003", "Spearphishing via Service")]),
    "social": TaxonomyEntry("social", "Social media",
                            "Delivered via a social-media direct message or post.",
                            [_mitre("T1566.003", "Spearphishing via Service")]),
    "voice_transcript": TaxonomyEntry(
        "voice_transcript", "Voice / vishing (transcript)",
        "Transcript of a voice-based lure (vishing), including AI-cloned voice.",
        [_mitre("T1566.004", "Spearphishing Voice")]),
}

# --- Axis 3: persuasion technique (the social-engineering lever) -------------------
# Grounded in Cialdini's principles of influence, plus coercive levers (fear, secrecy,
# urgency) that appear operationally in fraud but sit outside the classic six.
PERSUASION_TAXONOMY: Dict[str, TaxonomyEntry] = {
    "authority": TaxonomyEntry(
        "authority", "Authority",
        "Invoking a position of power or trusted institution (bank, IT, executive, agency).",
        [Crosswalk("Cialdini", "authority", "Authority principle")]),
    "urgency": TaxonomyEntry(
        "urgency", "Urgency / time pressure",
        "Imposing a deadline or immediate consequence to suppress deliberation.",
        [Crosswalk("Cialdini", "scarcity", "Scarcity principle (time variant)")]),
    "scarcity": TaxonomyEntry(
        "scarcity", "Scarcity",
        "Framing an opportunity or resource as limited or exclusive.",
        [Crosswalk("Cialdini", "scarcity", "Scarcity principle")]),
    "social_proof": TaxonomyEntry(
        "social_proof", "Social proof",
        "Citing others' participation or endorsement to normalize compliance.",
        [Crosswalk("Cialdini", "social_proof", "Social proof principle")]),
    "reciprocity": TaxonomyEntry(
        "reciprocity", "Reciprocity",
        "Offering a favor, gift, or refund to create a sense of obligation.",
        [Crosswalk("Cialdini", "reciprocity", "Reciprocity principle")]),
    "liking": TaxonomyEntry(
        "liking", "Liking / rapport",
        "Building affinity and trust, central to romance and long-con fraud.",
        [Crosswalk("Cialdini", "liking", "Liking principle")]),
    "commitment": TaxonomyEntry(
        "commitment", "Commitment / consistency",
        "Escalating from a small request to a large one to exploit consistency.",
        [Crosswalk("Cialdini", "commitment", "Commitment & consistency principle")]),
    "fear": TaxonomyEntry(
        "fear", "Fear / intimidation",
        "Threatening loss, penalty, legal action, or account suspension.",
        []),
    "secrecy": TaxonomyEntry(
        "secrecy", "Secrecy / isolation",
        "Instructing the target to keep the interaction confidential to prevent a "
        "reality check.",
        []),
}


def all_typologies() -> Dict[str, TaxonomyEntry]:
    return dict(TYPOLOGY_TAXONOMY)


def all_channels() -> Dict[str, TaxonomyEntry]:
    return dict(CHANNEL_TAXONOMY)


def all_persuasion() -> Dict[str, TaxonomyEntry]:
    return dict(PERSUASION_TAXONOMY)


def crosswalks_for(typology: str) -> List[Crosswalk]:
    entry = TYPOLOGY_TAXONOMY.get(typology)
    return list(entry.crosswalks) if entry else []


def validate() -> None:
    """Fail loudly if the taxonomy and the dataset schema have drifted apart."""
    missing_typ = TYPOLOGIES - set(TYPOLOGY_TAXONOMY)
    if missing_typ:
        raise ValueError(f"typologies in schema but not taxonomy: {sorted(missing_typ)}")
    extra_typ = set(TYPOLOGY_TAXONOMY) - TYPOLOGIES
    if extra_typ:
        raise ValueError(f"typologies in taxonomy but not schema: {sorted(extra_typ)}")
    missing_chan = CHANNELS - set(CHANNEL_TAXONOMY)
    if missing_chan:
        raise ValueError(f"channels in schema but not taxonomy: {sorted(missing_chan)}")

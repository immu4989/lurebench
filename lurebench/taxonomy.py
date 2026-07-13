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
  vocabularies line up; it is not endorsed by MITRE, FinCEN, or the FBI. Treat the
  external IDs as pointers to verify against the primary source, not as authority.
- **MITRE ATT&CK IDs are stable and precise here; the FinCEN/IC3 references name real
  programs but you should confirm the exact advisory against the issuing agency**, since
  advisory numbering changes and this file is a snapshot.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .schema import CHANNELS, TYPOLOGIES

TAXONOMY_VERSION = "1.0"

DISCLAIMER = (
    "LureBench-curated crosswalk. External framework references are editorial pointers "
    "for interoperability, not official designations by MITRE, FinCEN, or the FBI. "
    "Verify each reference against its primary source before operational use."
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
            Crosswalk("FBI/IC3", "phishing-spoofing", "Phishing/Spoofing crime type",
                      "https://www.ic3.gov"),
            Crosswalk("FinCEN", "", "GenAI-enabled fraud / deepfake media alert (2024)",
                      "https://www.fincen.gov"),
        ],
    ),
    "bec": TaxonomyEntry(
        "bec", "Business email compromise (BEC/EAC)",
        "Impersonation of an executive, vendor, or trusted party to redirect a payment "
        "or wire transfer.",
        [
            _mitre("T1566.002", "Spearphishing Link"),
            _mitre("T1656", "Impersonation"),
            Crosswalk("FBI/IC3", "bec-eac", "Business Email Compromise / Email Account Compromise",
                      "https://www.ic3.gov"),
            Crosswalk("FinCEN", "", "Advisory on email compromise fraud schemes",
                      "https://www.fincen.gov"),
        ],
    ),
    "romance": TaxonomyEntry(
        "romance", "Romance / confidence fraud",
        "A fabricated personal relationship built over time to extract money or "
        "financial access from the target.",
        [
            _mitre("T1656", "Impersonation"),
            Crosswalk("FBI/IC3", "confidence-romance", "Confidence Fraud / Romance",
                      "https://www.ic3.gov"),
        ],
    ),
    "pig_butchering": TaxonomyEntry(
        "pig_butchering", "Pig-butchering / investment fraud",
        "A long-con romance-plus-investment hybrid steering the target into a fraudulent "
        "(often crypto) investment platform.",
        [
            _mitre("T1656", "Impersonation"),
            Crosswalk("FBI/IC3", "investment", "Investment fraud (incl. crypto-investment)",
                      "https://www.ic3.gov"),
            Crosswalk("FinCEN", "FIN-2023-Alert006",
                      "Alert on the virtual-currency investment scam known as pig butchering",
                      "https://www.fincen.gov"),
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

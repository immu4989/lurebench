"""Claude-backed generator for controlled synthetic-lure generation.

Produces defanged, clearly-synthetic examples of a fraud typology for the sole
purpose of training and evaluating fraud detectors. The system prompt constrains
output to placeholders and forbids real people, organisations, payment details,
or live infrastructure. Requests that the model declines (``stop_reason ==
"refusal"``) are skipped, not retried around.

Install the extra:  pip install "lurebench[generate]"
Auth: set ANTHROPIC_API_KEY, or run `ant auth login` (a bare client picks it up).
"""

from __future__ import annotations

from typing import List

from .base import GenerationSpec, Generator

# Defaults to the current most-capable Opus-tier model. Any model works; note that
# Claude Fable 5 runs cyber safety classifiers and may decline more often — set
# `model="claude-fable-5"` only if you also want the server-side fallback path.
_DEFAULT_MODEL = "claude-opus-4-8"

_SYSTEM = (
    "You generate synthetic, clearly-fictional example messages used ONLY to train "
    "and evaluate automated fraud-detection models for a defensive security benchmark "
    "(LureBench). Hard rules for every message you write:\n"
    "- Use the placeholders <<link>> for any URL and <<contact>> for any phone/handle/email. "
    "Never write a real or realistic URL, address, phone number, or payment detail.\n"
    "- Never name a real person, company, bank, or government body. Use generic roles only.\n"
    "- Do not include operational instructions, malware, or anything beyond the message text.\n"
    "- Output ONLY the message text — no preamble, no explanation, no quotes."
)


class AnthropicGenerator(Generator):
    name = "anthropic"
    requires = ["anthropic"]

    def __init__(self, model: str = _DEFAULT_MODEL, max_tokens: int = 1024) -> None:
        try:
            import anthropic  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "AnthropicGenerator requires the 'generate' extra: pip install 'lurebench[generate]'"
            ) from exc
        self._anthropic = anthropic
        self._client = anthropic.Anthropic()
        self.model = model
        self.max_tokens = max_tokens

    def _user_prompt(self, spec: GenerationSpec) -> str:
        persona = spec.persona or "a generic, unremarkable scenario"
        persuasion = ", ".join(spec.persuasion) if spec.persuasion else "any plausible angle"
        return (
            f"Write one synthetic {spec.typology.replace('_', ' ')} lure delivered over "
            f"{spec.channel} in {spec.language}. Scenario seed: {persona}. "
            f"Persuasion emphasis: {persuasion}. Remember the placeholder and no-real-entity rules."
        )

    def generate(self, spec: GenerationSpec, n: int) -> List[str]:
        spec.validate()
        out: List[str] = []
        for _ in range(n):
            try:
                resp = self._client.messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    system=_SYSTEM,
                    messages=[{"role": "user", "content": self._user_prompt(spec)}],
                )
            except self._anthropic.APIStatusError:
                # Transient/API errors: skip this item rather than aborting the batch.
                continue
            if getattr(resp, "stop_reason", None) == "refusal":
                # The model declined; do not retry around a safety decision.
                continue
            text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text").strip()
            if text:
                out.append(text)
        return out

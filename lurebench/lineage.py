"""Conservative connected components of explicit message ancestry annotations.

These are declared relationships, not inferred semantic similarity or evidence
that unrelated components are independent. No network, model, or text matching.
"""

from collections.abc import Sequence

from .schema import Lure

LINEAGE_FIELDS = ("family_id", "scenario_id", "parent_id", "seed_id", "rewrite_of")


def lineage_components(records: Sequence[Lure]) -> dict[str, str]:
    """Map unique record IDs to deterministic explicit-lineage component labels.

    Record IDs and annotation references share a namespace, so references to a
    present parent connect to its own annotations transitively. References to
    absent parents still group their children. All populated fields contribute;
    conflicting annotations conservatively merge rather than silently choosing
    one. Component labels are stable under record reordering, not corpus changes.
    """
    parents: dict[str, str] = {}
    sizes: dict[str, int] = {}

    def token(value):
        if not isinstance(value, str) or not 1 <= len(value) <= 1024 or any(
            ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value
        ):
            raise ValueError("lineage identifiers must be bounded strings without controls")
        parents.setdefault(value, value)
        sizes.setdefault(value, 1)
        return value

    def find(value):
        while parents[value] != value:
            parents[value] = parents[parents[value]]
            value = parents[value]
        return value

    def join(left, right):
        left, right = find(left), find(right)
        if left == right:
            return
        if sizes[left] < sizes[right]:
            left, right = right, left
        parents[right] = left
        sizes[left] += sizes[right]

    ids = set()
    for record in records:
        identifier = token(record.id)
        if identifier in ids:
            raise ValueError("lineage analysis requires unique record IDs")
        ids.add(identifier)
        for field in LINEAGE_FIELDS:
            value = record.meta.get(field)
            if value is not None:
                join(identifier, token(value))
    # Prefer explicit annotation tokens when available, retaining recognizable
    # family labels for the common one-family-field case.
    annotations = {record.meta[field] for record in records for field in LINEAGE_FIELDS
                   if record.meta.get(field) is not None}
    members: dict[str, list[str]] = {}
    for value in parents:
        members.setdefault(find(value), []).append(value)
    labels = {root: min((value for value in values if value in annotations), default=min(values))
              for root, values in members.items()}
    return {identifier: labels[find(identifier)] for identifier in sorted(ids)}

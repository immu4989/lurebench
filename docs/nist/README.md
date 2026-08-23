# NIST AI Metrology submission draft

[`operational-adversarial-robustness-evaluation.yaml`](operational-adversarial-robustness-evaluation.yaml)
is a local draft in the official NIST AI Metrology Center 1.0 submission shape.
It is not a NIST publication, acceptance, evaluation, or endorsement.

The contact is intentionally `replace-before-submission@example.invalid`. This
prevents the repository draft from presenting a personal address and makes it
unsuitable for submission until the maintainer explicitly chooses a professional
contact and reviews the attribution.

Before proposing it to `usnistgov/ai-metrology-submissions`:

1. review the method and every claimed scope boundary;
2. replace the contact placeholder with the approved professional address;
3. re-check the current upstream `SUBMISSION_FORMAT.md` and schema;
4. validate the file with the upstream repository’s validator;
5. open a separate pull request to NIST and respond to reviewer feedback.

For a local schema check, download the current official schema and run:

```bash
curl -fsSLo /tmp/nist-ai-metrology-v1.json \
  https://raw.githubusercontent.com/usnistgov/ai-metrology-submissions/main/validation/schemas/v1.json
python scripts/validate_nist_submission_draft.py \
  --schema /tmp/nist-ai-metrology-v1.json --allow-placeholder
```

Omit `--allow-placeholder` for a submission-readiness check; the command will
then fail until the placeholder has been deliberately replaced.


# Incorporated and referenced sources

Each dataset LureBench ingests or maps to is listed here with its license and
citation. Sources whose license forbids redistribution are **pointer-only**: the
build reads a locally-downloaded copy and never re-hosts the raw text.

Confirm every license against the upstream page before release — the notes below
record what was observed during the prior-art scan and must be re-verified.

## AI-generated / mixed phishing corpora

| Source | Coverage | Provenance | Redistribute? | Citation |
|---|---|---|---|---|
| Greco et al., Human-LLM Phishing/Legit (Kaggle) | ~4k emails, EN | human + AI (ChatGPT, WormGPT) | verify Kaggle terms | Greco, Desolda, Esposito, Carelli, *David vs. Goliath*, ITASEC 2024 |
| e-PhishGen / E-PhishLLM | phishing + legit, EN + IT | AI | check repo LICENSE | Pajola et al., *E-PhishGen*, ACM AISec 2025 |
| DataPhish / PhishingSpamDataSet | ~12k emails, phishing/spam/legit | human + AI (multi-model) | check repo LICENSE | arXiv 2511.21448 |
| GPT-o1 Cialdini-labeled phishing | ~2,995 emails, persuasion-labeled | AI (GPT-o1) | verify | MDPI *Computers* 14(12):523 |

## Romance / pig-butchering

| Source | Coverage | Provenance | Redistribute? | Citation |
|---|---|---|---|---|
| Romance-baiting synthetic dialogues | 250 GPT-4.1 dialogues + controls | AI | dataset promised public; code withheld | arXiv 2512.16280 |

## Human baselines and benign controls

| Source | Coverage | Provenance | Redistribute? | Citation |
|---|---|---|---|---|
| Nazario phishing corpus | human phishing | human | pointer-only, verify | J. Nazario phishing corpus |
| Nigerian Fraudulent ("419") | advance-fee fraud | human | verify | public 419 corpus |
| SpamAssassin public corpus | spam + ham | human | Apache-friendly, verify | apache.org/old/publiccorpus |
| Enron email (ham) | benign email | human | public | Klimt & Yang, 2004 |
| PhishTank | reported phishing URLs/text | human | API terms apply | phishtank.org |

## Reference-only (not ingested)

| Source | Why referenced |
|---|---|
| RAID (liamdugan/raid) | design template; general MGT detection, no fraud domains |
| Binoculars (ahans30/Binoculars) | provenance baseline detector |
| SoK: LLM-generated phishing (arXiv 2508.21457) | landscape + detector list |
| ASVspoof 5 / Deepfake-Eval-2024 / VishGPT | audio/video modality — out of LureBench text scope |

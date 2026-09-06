# ALU Regex Data Extraction & Secure Validation

Extracts structured data from raw, messy text and validates it defensively.

## Extracts
- Emails, incl. ALU tiers: `alu_official`, `alu_alumni`, `alu_si`
- Credit cards (Luhn-validated, last 4 digits only)
- URLs (http/https), phone numbers, times, HTML tags (safe tags only), hashtags, currency

## Security
- Injection patterns (script tags, SQLi, path traversal, template injection) are counted, never reproduced
- Invalid credit cards (fail Luhn) are rejected
- Emails/cards are masked before output
- Input size capped

## Run
```bash
python src/main.py
```
Reads `input/raw-text.txt`, writes `output/sample-output.json`.

## Structure
```
├── input/raw-text.txt
├── src/main.py
├── output/sample-output.json
└── README.md
``` 
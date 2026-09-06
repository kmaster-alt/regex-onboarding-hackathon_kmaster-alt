import re
import json
import os

MAX_INPUT_BYTES = 200_000  # guard against oversized/DoS-style input

# Injection-style patterns — counted only, payload never stored/printed
SUSPICIOUS_PATTERNS = {
    "script_tag": re.compile(r"<script\b.*?>.*?</script\s*>", re.IGNORECASE | re.DOTALL),
    "event_handler_attr": re.compile(r'on\w+\s*=\s*["\'].*?["\']', re.IGNORECASE),
    "javascript_uri": re.compile(r"javascript\s*:", re.IGNORECASE),
    "sql_injection": re.compile(r"['\"]\s*(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.IGNORECASE),
    "path_traversal": re.compile(r"\.\./"),
    "template_injection": re.compile(r"\{\{.*?\}\}"),
}

PATTERNS = {
    "emails": re.compile(  # local@domain.tld, rejects malformed domains
        r"\b[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,63}[A-Za-z0-9])?"
        r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b"
    ),
    "urls": re.compile(r"\bhttps?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/[^\s\"'<>]*)?"),  # http/https only
    "phones": re.compile(  # optional country code + area code + grouped digits
        r"(?<!\d)(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{2,4}(?:[\s.-]?\d{3,4}){1,3}(?!\d)"
    ),
    "credit_cards": re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),  # Luhn-checked later
    "times": re.compile(r"\b(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d)?\s?(?:[AaPp][Mm])?\b"),  # 24h or 12h
    "html_tags": re.compile(r"</?(?:p|div|span|br|b|i|strong|em|a|ul|li|h[1-6])\b[^>]*>", re.IGNORECASE),  # safe tags only
    "hashtags": re.compile(r"#[A-Za-z][A-Za-z0-9_]{1,49}\b"),
    "currency": re.compile(r"(?:[$€£]|RWF|USD|EUR)\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?"),
}

# Domain tail decides ALU tier — check most specific subdomain first
ALU_PATTERNS = {
    "alu_si": re.compile(r"^[A-Za-z0-9._%+-]+@si\.alueducation\.com$", re.IGNORECASE),
    "alu_alumni": re.compile(r"^[A-Za-z0-9._%+-]+@alumni\.alueducation\.com$", re.IGNORECASE),
    "alu_official": re.compile(r"^[A-Za-z0-9._%+-]+@alueducation\.com$", re.IGNORECASE),
}


def scan_for_threats(text):
    """Count unsafe patterns without storing the matched payload."""
    findings = {}
    for name, pattern in SUSPICIOUS_PATTERNS.items():
        count = len(pattern.findall(text))
        if count:
            findings[name] = count
    return findings


def luhn_valid(number):
    """Luhn checksum — rejects fake/typo card numbers."""
    digits = [int(d) for d in number]
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def mask_email(email):
    """Show first 2 chars of local-part only."""
    local, _, domain = email.partition("@")
    visible = local[:2]
    return f"{visible}{'*' * max(len(local) - 2, 1)}@{domain}"


def mask_card(digits):
    """Only last 4 digits ever leave this function."""
    return f"**** **** **** {digits[-4:]}"


def classify_email(email):
    for tier, pattern in ALU_PATTERNS.items():
        if pattern.match(email):
            return tier
    return "general"


def extract_all(text):
    result = {}

    emails_found = sorted(set(PATTERNS["emails"].findall(text)))
    result["emails"] = [
        {"masked": mask_email(e), "tier": classify_email(e)} for e in emails_found
    ]

    # Validate + mask cards, drop anything that fails Luhn
    card_matches = list(PATTERNS["credit_cards"].finditer(text))
    valid_cards, rejected = [], 0
    for m in card_matches:
        digits = re.sub(r"[ -]", "", m.group())
        if 13 <= len(digits) <= 16 and luhn_valid(digits):
            valid_cards.append(mask_card(digits))
        else:
            rejected += 1
    result["credit_cards"] = sorted(set(valid_cards))
    result["credit_cards_rejected_invalid"] = rejected

    # Blank card digits first so they're not double-counted as phones
    text_for_phones = text
    for m in card_matches:
        text_for_phones = text_for_phones[: m.start()] + " " * (m.end() - m.start()) + text_for_phones[m.end() :]
    result["phones"] = sorted(set(m.strip() for m in PATTERNS["phones"].findall(text_for_phones)))

    for key in ("urls", "times", "html_tags", "hashtags", "currency"):
        result[key] = sorted(set(m.strip() for m in PATTERNS[key].findall(text)))

    return result


def main():
    input_path = os.path.join("input", "raw-text.txt")
    output_path = os.path.join("output", "sample-output.json")

    with open(input_path, "rb") as f:
        raw_bytes = f.read(MAX_INPUT_BYTES + 1)

    if len(raw_bytes) > MAX_INPUT_BYTES:
        raise ValueError("Input exceeds trusted size limit - refusing to process.")

    text = raw_bytes.decode("utf-8", errors="replace")  # never trust source encoding

    threats = scan_for_threats(text)
    extracted = extract_all(text)

    report = {
        "security_flags": threats,
        "note": "Suspicious content is counted, never reproduced, and excluded from results.",
        "extracted": extracted,
    }

    os.makedirs("output", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("=== Extraction Summary ===")
    for key, value in extracted.items():
        if isinstance(value, list):
            print(f"{key}: {len(value)} found")
    print(f"Security flags: {threats if threats else 'none'}")
    print(f"Full report written to {output_path}")


if __name__ == "__main__":
    main()
    
import re

REDACTION_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)((?:api[_-]?key|token|password|passwd|secret)\s*[:=]\s*)\S+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
)


def redact_text(value: str) -> str:
    redacted = value
    for pattern in REDACTION_PATTERNS:
        if pattern.groups:
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
        else:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def redact_mapping(values: dict[str, str]) -> dict[str, str]:
    return {key: redact_text(value) for key, value in values.items()}

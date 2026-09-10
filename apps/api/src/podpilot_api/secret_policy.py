"""Presentation policy for delegated Secret work; never changes cluster access."""

import json
import re

import yaml

from podpilot_diagnostics.redaction import redact_text


_PRIVATE_KEY = re.compile(
    r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?(?:-----END \1-----|$)",
    re.DOTALL,
)
_FENCE = re.compile(r"(```[^\n]*\n)(.*?)(\n```)", re.DOTALL)


def redact_secret_output(value: str) -> str:
    """Redact structured Secret exports and credential patterns, keeping public certs.

    Arbitrary shell transformations cannot be inferred from the returned text.
    Agents must project non-sensitive findings inside the runner.
    """
    value = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", value)

    def clean(item: object) -> object:
        if isinstance(item, list):
            return [clean(child) for child in item]
        if isinstance(item, dict):
            secret = str(item.get("kind", "")).casefold() == "secret"
            return {
                key: (
                    {name: "[REDACTED]" for name in child}
                    if secret and key in {"data", "stringData"} and isinstance(child, dict)
                    else "[REDACTED]"
                    if key == "kubectl.kubernetes.io/last-applied-configuration"
                    else clean(child)
                )
                for key, child in item.items()
            }
        if isinstance(item, str):
            return redact_text(_PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", item))
        return item

    def structured(text: str) -> str:
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            try:
                documents = list(yaml.safe_load_all(text))
                cleaned = [clean(document) for document in documents]
                if cleaned != documents:
                    return yaml.safe_dump_all(cleaned, sort_keys=False)
            except (yaml.YAMLError, RecursionError):
                pass
            return redact_text(text)
        cleaned = clean(parsed)
        return json.dumps(cleaned, ensure_ascii=False) if cleaned != parsed else redact_text(text)

    value = _FENCE.sub(lambda match: match[1] + structured(match[2]) + match[3], value)
    return structured(value)

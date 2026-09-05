from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from podpilot_api.database import build_engine
from podpilot_api.model_provider import ModelProfileConfig, OpenAIProviderRouter
from podpilot_api.models import AuditEvent, ModelProfile
from podpilot_api.settings import get_settings
from podpilot_openshift.credentials import KubernetesSecretCredentialStore


PROVIDER_LABEL = "OpenRouter lab"
BASE_URL = "https://openrouter.ai/api/v1"
CHAT_MODEL = "openai/gpt-oss-120b"
API_TYPE = "chat-completions"
CREDENTIAL_KEY = "openrouter_api_key"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Configure and probe the fixed lab OpenRouter agent profile."
    )
    parser.add_argument("--credential-stdin", action="store_true")
    args = parser.parse_args()
    settings = get_settings()
    if settings.environment != "sno-lab":
        print("The OpenRouter bootstrap is restricted to the SNO lab deployment.")
        return 2

    store = KubernetesSecretCredentialStore(
        settings.model_secret_namespace,
        settings.model_secret_name,
        settings.model_secret_key,
    )
    if args.credential_stdin:
        credential = sys.stdin.read().strip()
        if len(credential) < 8:
            print("No usable OpenRouter credential was supplied on stdin.")
            return 2
        store.set(credential, CREDENTIAL_KEY)
    credential = store.get(CREDENTIAL_KEY)
    if not credential:
        print("The OpenRouter credential key is not configured.")
        return 2

    engine = build_engine(settings)
    now = datetime.now(timezone.utc)
    with Session(engine) as db_session:
        profile = db_session.scalar(select(ModelProfile).where(
            ModelProfile.provider_label == PROVIDER_LABEL
        ))
        if profile is None:
            profile = ModelProfile(
                provider_label=PROVIDER_LABEL,
                credential_key=CREDENTIAL_KEY,
                updated_by="system:openrouter-lab-bootstrap",
            )
        db_session.execute(update(ModelProfile).values(is_active=False))
        profile.base_url = BASE_URL
        profile.chat_model = CHAT_MODEL
        profile.api_type = API_TYPE
        profile.credential_key = CREDENTIAL_KEY
        profile.tls_mode = "system"
        profile.custom_ca_pem = None
        profile.max_input_tokens = 131_072
        profile.max_output_tokens = 16_384
        profile.timeout_seconds = 180
        profile.max_retries = 3
        profile.temperature = None
        profile.reasoning_effort = "high"
        profile.reasoning_efforts_json = json.dumps(["low", "medium", "high"])
        profile.embedding_model = None
        profile.tool_calling_hint = True
        profile.vision_hint = False
        profile.is_active = True
        profile.status = "not_tested"
        profile.capabilities_json = "{}"
        profile.last_error = None
        profile.last_probe_diagnostics_json = "{}"
        profile.last_probe_at = None
        profile.updated_by = "system:openrouter-lab-bootstrap"
        profile.updated_at = now
        db_session.add(profile)
        db_session.commit()
        profile_id = profile.id

    config = ModelProfileConfig(
        provider_label=PROVIDER_LABEL,
        base_url=BASE_URL,
        chat_model=CHAT_MODEL,
        embedding_model=None,
        timeout_seconds=180,
        max_output_tokens=16_384,
        api_type=API_TYPE,
        tls_mode="system",
        max_input_tokens=131_072,
        reasoning_effort="high",
        max_retries=3,
    )
    try:
        report = OpenAIProviderRouter().probe(config, credential)
        capabilities = report.to_dict()
        accepted_transport = any(
            capabilities.get(key) is True
            for key in ("tls_valid", "tls_accepted", "plaintext_accepted")
        )
        ready = accepted_transport and all(
            capabilities.get(key) is True
            for key in ("reachable", "authenticated", "model_available", "tool_calls")
        )
        status = "ready" if ready else "reduced_capability"
        error = None if ready else (
            report.ask_schema_error
            or "The OpenRouter endpoint did not pass the required tool-calling checks."
        )
    except Exception as exc:
        capabilities = {}
        status = "unavailable"
        error = f"Provider probe failed ({type(exc).__name__})."

    with Session(engine) as db_session:
        profile = db_session.get(ModelProfile, profile_id)
        assert profile is not None
        profile.status = status
        profile.capabilities_json = json.dumps(capabilities, sort_keys=True)
        profile.last_error = error
        profile.last_probe_at = datetime.now(timezone.utc)
        db_session.add(AuditEvent(
            actor="system:openrouter-lab-bootstrap",
            action="model_profile.bootstrap",
            outcome=status,
            details_json=json.dumps({
                "provider_label": PROVIDER_LABEL,
                "base_url": BASE_URL,
                "chat_model": CHAT_MODEL,
                "api_type": API_TYPE,
                "tool_calls": capabilities.get("tool_calls"),
            }, sort_keys=True),
        ))
        db_session.commit()
    engine.dispose()

    print(
        f"Configured {PROVIDER_LABEL}: {CHAT_MODEL} via {API_TYPE}; status={status}."
    )
    return 0 if status == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())

from datetime import datetime, timedelta, timezone

from podpilot_api.delegated_sessions import DelegatedSessionVault


def test_delegated_vault_scopes_connections_to_owner_and_session() -> None:
    vault = DelegatedSessionVault(lifetime_seconds=7200)
    connection = vault.put(
        session_id="s" * 32,
        owner="alice",
        cluster_id="dev-east",
        remote_username="alice",
        remote_uid="uid-alice",
        token="secret-token",
    )

    assert vault.get(
        session_id="s" * 32, owner="alice", cluster_id="dev-east"
    ) == connection
    assert vault.get(
        session_id="s" * 32, owner="bob", cluster_id="dev-east"
    ) is None
    assert vault.by_capability(connection.proxy_capability) == connection
    assert "secret-token" not in repr(connection)


def test_delegated_vault_drains_expired_tokens_for_revocation() -> None:
    vault = DelegatedSessionVault(lifetime_seconds=7200)
    connection = vault.put(
        session_id="s" * 32,
        owner="alice",
        cluster_id="dev-east",
        remote_username="alice",
        remote_uid="uid-alice",
        token="secret-token",
    )
    expired = connection.__class__(
        **{
            **connection.__dict__,
            "expires_at": datetime.now(timezone.utc) - timedelta(seconds=1),
        }
    )
    vault._connections[(expired.session_id, expired.cluster_id)] = expired

    assert vault.get(
        session_id="s" * 32, owner="alice", cluster_id="dev-east"
    ) is None
    assert vault.pop_expired() == [expired]


def test_delegated_vault_throttles_login_submissions_per_owner() -> None:
    vault = DelegatedSessionVault()

    assert vault.allow_login(owner="alice", attempts_per_minute=2) is True
    assert vault.allow_login(owner="alice", attempts_per_minute=2) is True
    assert vault.allow_login(owner="alice", attempts_per_minute=2) is False
    assert vault.allow_login(owner="bob", attempts_per_minute=2) is True

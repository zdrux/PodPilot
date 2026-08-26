from sqlalchemy import text

from podpilot_api.database import build_engine
from podpilot_api.settings import Settings


def test_sqlite_engine_enables_wal_and_waits_for_concurrent_writers(tmp_path) -> None:
    settings = Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'concurrent.db'}",
        role_investigator_groups=[],
        role_approver_groups=[],
        role_breakglass_groups=[],
    )

    engine = build_engine(settings)
    with engine.connect() as connection:
        journal_mode = connection.execute(text("PRAGMA journal_mode")).scalar_one()
        busy_timeout = connection.execute(text("PRAGMA busy_timeout")).scalar_one()
        synchronous = connection.execute(text("PRAGMA synchronous")).scalar_one()
    engine.dispose()

    assert str(journal_mode).lower() == "wal"
    assert busy_timeout == 30_000
    assert synchronous == 1

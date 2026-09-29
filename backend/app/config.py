"""Central configuration for the Evidence-First Forensic Platform.

All settings are offline-safe: the platform never requires a live Tor daemon
or an external database to run its testbed.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BACKEND_ROOT.parent


class Settings(BaseSettings):
    """Runtime configuration, overridable via environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="FORENSIC_", env_file=".env", extra="ignore"
    )

    app_name: str = "Evidence-First Forensic Platform"
    version: str = "1.0.0"
    environment: str = "development"

    # --- Persistence -----------------------------------------------------
    data_dir: Path = BACKEND_ROOT / "data"
    sqlite_filename: str = "forensic.db"

    # --- Testbed endpoints ------------------------------------------------
    # The "onion" is simulated locally so the entire platform is reproducible
    # offline. In production these values point at real SOCKS endpoints.
    mock_onion_base_url: str = "http://mock-onion:8080"
    mock_clearnet_base_url: str = "http://mock-clearnet:8081"
    probe_timeout_seconds: float = 5.0
    allow_network_probes: bool = True

    # --- Adjudication fusion weights (must sum to 1.0) -------------------
    weight_crypto: float = 0.40
    weight_infra: float = 0.25
    weight_temporal: float = 0.20
    weight_stylometry: float = 0.15

    # Contradiction downgrades applied on top of the fused score.
    contradiction_penalty: float = 0.35

    # --- Case metadata ---------------------------------------------------
    case_reference: str = "CASE-2026-DWF-0001"
    generating_officer: str = "Digital Forensics Unit / Examiner on Record"
    classification_level: str = "CONFIDENTIAL - LAW ENFORCEMENT SENSITIVE"

    cors_origins: List[str] = ["*"]

    @property
    def sqlite_path(self) -> Path:
        return self.data_dir / self.sqlite_filename

    @property
    def sqlite_url(self) -> str:
        return f"sqlite:///{self.sqlite_path}"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_dirs()

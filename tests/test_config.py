import pytest

from aquasec_mcp.config import AquaConfig


def test_config_defaults() -> None:
    config = AquaConfig()
    assert config.api_key is None
    assert config.api_secret is None
    assert config.base_url == "https://eu-central-1.edge.cloud.aquasec.com"
    assert config.token_url == "https://eu-1.api.cloudsploit.com/v2/tokens"
    assert config.read_only is False
    assert config.request_timeout == 30.0


def test_config_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AQUA_API_KEY", "test-key-123")
    monkeypatch.setenv("AQUA_API_SECRET", "test-secret-456")
    monkeypatch.setenv("AQUA_BASE_URL", "https://custom.aquasec.com")
    monkeypatch.setenv("AQUA_TOKEN_URL", "https://custom.cloudsploit.com/v2/tokens")
    monkeypatch.setenv("AQUA_READ_ONLY", "true")
    monkeypatch.setenv("AQUA_REQUEST_TIMEOUT", "45.5")

    config = AquaConfig.from_env()
    assert config.api_key == "test-key-123"
    assert config.api_secret == "test-secret-456"
    assert config.base_url == "https://custom.aquasec.com"
    assert config.token_url == "https://custom.cloudsploit.com/v2/tokens"
    assert config.read_only is True
    assert config.request_timeout == 45.5


def test_config_validate_credentials() -> None:
    empty_config = AquaConfig()
    with pytest.raises(ValueError, match="AQUA_API_KEY and AQUA_API_SECRET must be set"):
        empty_config.validate_credentials()

    valid_config = AquaConfig(api_key="key", api_secret="secret")
    valid_config.validate_credentials()  # should not raise


def test_config_from_dotenv(tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "AQUA_API_KEY=dotenv-key\n"
        "AQUA_API_SECRET=dotenv-secret\n"
        "AQUA_READ_ONLY=1\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AQUA_API_KEY", raising=False)
    monkeypatch.delenv("AQUA_API_SECRET", raising=False)
    monkeypatch.delenv("AQUA_READ_ONLY", raising=False)

    config = AquaConfig.from_env()
    assert config.api_key == "dotenv-key"
    assert config.api_secret == "dotenv-secret"
    assert config.read_only is True

import pytest
import httpx
from unittest.mock import AsyncMock, patch
from app.core.config import settings
from app.services.threat_intelligence import query_virustotal_url, encode_url_for_vt


def test_encode_url_for_vt():
    url = "http://example.com/phish"
    encoded = encode_url_for_vt(url)
    assert "=" not in encoded
    assert len(encoded) > 0


@pytest.mark.anyio
async def test_virustotal_unconfigured_key():
    with patch.object(settings, "VIRUSTOTAL_API_KEY", "your_vt_api_key_here"):
        result = await query_virustotal_url("http://example.com/test")
        assert result.status == "unconfigured"
        assert result.has_intel is False
        assert any("unconfigured" in lim.lower() for lim in result.limitations)


@pytest.mark.anyio
async def test_virustotal_rate_limit_fallback():
    mock_response = httpx.Response(status_code=429)
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch.object(settings, "VIRUSTOTAL_API_KEY", "real_test_key_12345"):
        result = await query_virustotal_url("http://suspicious-site.com", client=mock_client)
        assert result.status == "rate_limited"
        assert any("429" in lim for lim in result.limitations)


@pytest.mark.anyio
async def test_virustotal_successful_detection():
    mock_payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 8,
                    "suspicious": 3,
                    "harmless": 50,
                    "undetected": 10
                },
                "reputation": -50
            }
        }
    }
    mock_response = httpx.Response(status_code=200, json=mock_payload)
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch.object(settings, "VIRUSTOTAL_API_KEY", "real_test_key_12345"):
        result = await query_virustotal_url("http://confirmed-phish.net", client=mock_client)
        assert result.status == "malicious"
        assert result.malicious_count == 8
        assert result.suspicious_count == 3
        assert len(result.indicators) >= 1
        ind = result.indicators[0]
        assert ind["source"] == "VIRUSTOTAL_API_V3"
        assert "External third-party" in ind["description"]


@pytest.mark.anyio
async def test_virustotal_network_timeout():
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("Read timed out"))

    with patch.object(settings, "VIRUSTOTAL_API_KEY", "real_test_key_12345"):
        result = await query_virustotal_url("http://timeout-site.com", client=mock_client)
        assert result.status == "error"
        assert any("timed out" in lim.lower() for lim in result.limitations)

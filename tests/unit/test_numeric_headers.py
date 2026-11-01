import httpx
import pytest

from scanproof.connectors.base import ConnectorError, ErrorKind
from scanproof.connectors.gitlab import GitLabConnector
from scanproof.connectors.http import parse_retry_after


@pytest.mark.parametrize("value", ["\u00b2", "\u0661\u0662", "\uff11\uff12"])
def test_retry_after_rejects_non_ascii_numbers(value):
    assert parse_retry_after(value) is None


def test_oversized_content_length_fails_without_integer_conversion_crash():
    response = httpx.Response(200, content=b"{}", headers={"Content-Length": "9" * 5000})
    with (
        GitLabConnector(
            "https://example.com",
            None,
            anonymous=True,
            transport=httpx.MockTransport(lambda request: response),
        ) as conn,
        pytest.raises(ConnectorError) as exc,
    ):
        conn.download_artifact_file("123", 1, "report.json")
    assert exc.value.kind is ErrorKind.LIMIT_EXCEEDED


def test_content_length_leading_zeros_is_valid():
    response = httpx.Response(200, content=b"{}", headers={"Content-Length": "0" * 5000 + "2"})
    with GitLabConnector(
        "https://example.com",
        None,
        anonymous=True,
        transport=httpx.MockTransport(lambda request: response),
    ) as conn:
        assert conn.download_artifact_file("123", 1, "report.json") == b"{}"

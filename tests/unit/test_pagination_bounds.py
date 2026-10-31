import httpx
import pytest

from scanproof.connectors.base import ConnectorError, ErrorKind
from scanproof.connectors.gitlab import GitLabConnector


@pytest.mark.parametrize("header", ["9" * 5000, "²"])
def test_malformed_page_number_is_indeterminate(header):
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200, json=[{}], headers={"x-next-page": header.encode("utf-8")}
        )
    )
    with (
        GitLabConnector("https://example.com", None, anonymous=True, transport=transport) as conn,
        pytest.raises(ConnectorError) as exc,
    ):
        list(conn._paginate("/jobs", {}))
    assert exc.value.kind is ErrorKind.INVALID_RESPONSE

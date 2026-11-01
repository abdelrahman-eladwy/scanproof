"""origin_of() decides where credentials may be sent and which links are followed.

The API origin is compared per request (Authorization header) and per redirect and
pagination link, so a parsing surprise there is a credential-safety question.
"""

from __future__ import annotations

from scanproof.connectors.http import is_loopback, origin_of


def test_origin_normalizes_scheme_host_and_port() -> None:
    assert origin_of("https://API.GitHub.com") == ("https", "api.github.com", 443)
    assert origin_of("https://gitlab.example.com:8443/x") == ("https", "gitlab.example.com", 8443)
    assert origin_of("http://127.0.0.1:8080/a") == ("http", "127.0.0.1", 8080)


def test_malformed_authority_names_no_origin() -> None:
    """urlsplit().port raises ValueError; a server-supplied Link header must not crash us.

    An empty origin matches no configured origin, so no credential is sent to it.
    """
    assert origin_of("https://host:not-a-port/x") == ("", "", None)
    assert origin_of("https://host:99999/x") == ("", "", None)


def test_loopback_hosts() -> None:
    assert is_loopback("http://localhost:3000") and is_loopback("http://[::1]:80")
    assert not is_loopback("https://gitlab.com")

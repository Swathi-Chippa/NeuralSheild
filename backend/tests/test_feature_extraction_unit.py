import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from feature_extraction import (
    _at_symbol_feature,
    _double_slash_feature,
    _https_token_feature,
    _ip_address_feature,
    _prefix_suffix_feature,
    _subdomain_feature,
    _url_length_feature,
)


@pytest.mark.parametrize("url, expected", [("http://192.168.1.1/login", -1), ("https://example.com", 1)])
def test_having_ip_address(url, expected):
    assert _ip_address_feature(url) == expected


@pytest.mark.parametrize(
    "url, expected",
    [("https://a.co", 1), ("https://" + "a" * 50 + ".com", 0), ("https://" + "a" * 80 + ".com", -1)],
)
def test_url_length(url, expected):
    assert _url_length_feature(url) == expected


@pytest.mark.parametrize("url, expected", [("https://user@example.com", -1), ("https://example.com", 1)])
def test_at_symbol(url, expected):
    assert _at_symbol_feature(url) == expected


@pytest.mark.parametrize("url, expected", [("https://example.com//redirect", -1), ("https://example.com/path", 1)])
def test_double_slash_redirecting(url, expected):
    assert _double_slash_feature(url) == expected


@pytest.mark.parametrize("url, expected", [("https://secure-login.example.com", -1), ("https://example.com", 1)])
def test_prefix_suffix(url, expected):
    assert _prefix_suffix_feature(url) == expected


@pytest.mark.parametrize(
    "url, expected",
    [("https://example.com", 1), ("https://shop.example.com", 0), ("https://a.b.example.com", -1)],
)
def test_having_sub_domain(url, expected):
    assert _subdomain_feature(url) == expected


@pytest.mark.parametrize("url, expected", [("https://https-example.com", -1), ("https://example.com", 1)])
def test_https_token(url, expected):
    assert _https_token_feature(url) == expected

"""Feature extraction for the 28-column phishing model."""

from __future__ import annotations

import functools
import ipaddress
import logging
import os
import re
import socket
import ssl
import tempfile
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urljoin, urlparse

import requests
import tldextract
import whois
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from tranco import Tranco


logger = logging.getLogger(__name__)
load_dotenv()

OPENPAGERANK_API_KEY = os.environ.get("OPENPAGERANK_API_KEY")
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
if not OPENPAGERANK_API_KEY:
    logger.warning("OPENPAGERANK_API_KEY is not configured; Page_Rank will use -1.")
if not GOOGLE_SAFE_BROWSING_API_KEY:
    logger.warning(
        "GOOGLE_SAFE_BROWSING_API_KEY is not configured; "
        "Statistical_report will use its fail-open value of 1."
    )


FEATURE_NAMES = [
    "having_IPhaving_IP_Address",
    "URLURL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "Domain_registeration_length",
    "Favicon",
    "port",
    "HTTPS_token",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Abnormal_URL",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWidnow",
    "Iframe",
    "age_of_domain",
    "DNSRecord",
    "web_traffic",
    "Page_Rank",
    "Statistical_report",
]


class SSRFBlockedError(Exception):
    """Raised when a hostname resolves to a non-public or otherwise unsafe IP."""


def _parse_url(url: str):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
    except ValueError as exc:
        raise requests.exceptions.InvalidURL(str(exc)) from exc
    if parsed.scheme not in {"http", "https"}:
        raise requests.exceptions.InvalidURL(
            "Only http and https URLs are supported."
        )
    if not hostname:
        raise requests.exceptions.InvalidURL("URL must contain a hostname.")
    return parsed, hostname


def _unsafe_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(
        (
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_reserved,
            ip.is_multicast,
            ip.is_unspecified,
        )
    )


def resolve_and_validate_host(hostname: str) -> list[str]:
    """Resolve every address for a host and reject any non-public address."""
    try:
        address_info = socket.getaddrinfo(hostname, None)
    except OSError:
        raise

    validated: list[str] = []
    for item in address_info:
        address = item[4][0]
        ip = ipaddress.ip_address(address)
        if _unsafe_ip(ip):
            raise SSRFBlockedError(
                f"Refusing hostname {hostname!r}: it resolves to unsafe IP {ip}."
            )
        if str(ip) not in validated:
            validated.append(str(ip))
    if not validated:
        raise socket.gaierror(f"No addresses resolved for {hostname!r}.")
    return validated


def _validated_request_url(url: str) -> tuple[str, str]:
    parsed, hostname = _parse_url(url)
    resolve_and_validate_host(hostname)
    return parsed.geturl(), hostname


def _safe_get_with_hops(url: str, **kwargs) -> tuple[requests.Response, int]:
    current_url = url
    hops = 0
    request_kwargs = dict(kwargs)
    request_kwargs.pop("allow_redirects", None)
    request_kwargs.pop("timeout", None)

    while True:
        current_url, _ = _validated_request_url(current_url)
        response = requests.get(
            current_url,
            allow_redirects=False,
            timeout=(5, 10),
            **request_kwargs,
        )
        location = response.headers.get("Location")
        if not (300 <= response.status_code < 400 and location):
            return response, hops
        if hops >= 3:
            raise requests.exceptions.TooManyRedirects(
                "Maximum of 3 validated redirect hops exceeded."
            )
        current_url = urljoin(current_url, location)
        _parse_url(current_url)
        hops += 1


def safe_get(url: str, **kwargs) -> requests.Response:
    """GET a URL only after validating every host and redirect target."""
    response, hops = _safe_get_with_hops(url, **kwargs)
    response._validated_redirect_hops = hops
    return response


def _safe_api_post(url: str, **kwargs) -> requests.Response:
    """POST only to a fixed, public API host after the same SSRF validation."""
    current_url, _ = _validated_request_url(url)
    request_kwargs = dict(kwargs)
    request_kwargs.pop("allow_redirects", None)
    request_kwargs.pop("timeout", None)
    return requests.post(
        current_url,
        allow_redirects=False,
        timeout=(5, 10),
        **request_kwargs,
    )


def _fail_closed(function: Callable[..., int]) -> Callable[..., int]:
    """Make network/DNS feature failures return the phishing value."""
    @functools.wraps(function)
    def wrapper(*args, **kwargs) -> int:
        try:
            return int(function(*args, **kwargs))
        except Exception as exc:  # Feature isolation is intentional.
            logger.debug("Feature %s failed: %s", function.__name__, exc)
            return -1

    return wrapper


def _hostname(url: str) -> str:
    _, hostname = _parse_url(url)
    return hostname.lower().rstrip(".")


def _parse_literal_ip(hostname: str):
    candidate = hostname.strip("[]").lower()
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass

    def number(part: str) -> int:
        if part.lower().startswith("0x"):
            return int(part, 16)
        if len(part) > 1 and part.startswith("0"):
            return int(part, 8)
        return int(part, 10)

    try:
        parts = candidate.split(".")
        if len(parts) == 1:
            value = number(parts[0])
            return ipaddress.IPv4Address(value) if value <= 0xFFFFFFFF else None
        if len(parts) not in {2, 3, 4}:
            return None
        values = [number(part) for part in parts]
        limits = {2: [255, 0xFFFFFFFF], 3: [255, 255, 0xFFFF], 4: [255] * 4}
        if any(value > limit for value, limit in zip(values, limits[len(values)])):
            return None
        if len(values) == 2:
            packed = (values[0] << 24) | values[1]
        elif len(values) == 3:
            packed = (values[0] << 24) | (values[1] << 16) | values[2]
        else:
            packed = (
                (values[0] << 24)
                | (values[1] << 16)
                | (values[2] << 8)
                | values[3]
            )
        return ipaddress.IPv4Address(packed)
    except (TypeError, ValueError):
        return None


def _extractor():
    return tldextract.TLDExtract(suffix_list_urls=())


def _page(url: str) -> tuple[requests.Response, BeautifulSoup, str]:
    response = safe_get(url)
    response.raise_for_status()
    page_hostname = _hostname(url)
    return response, BeautifulSoup(response.text, "html.parser"), page_hostname


def _same_domain(target_url: str, page_hostname: str) -> bool:
    try:
        target_hostname = urlparse(target_url).hostname
    except ValueError:
        return False
    return bool(target_hostname) and target_hostname.lower().rstrip(".") == page_hostname


def _date_value(value: Any) -> datetime | None:
    if isinstance(value, (list, tuple)):
        values = [_date_value(item) for item in value]
        values = [item for item in values if item is not None]
        return min(values) if values else None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        return datetime.combine(value, datetime.min.time(), tzinfo=timezone.utc)
    return None


def _whois_record(domain: str):
    return whois.whois(domain)


def _static_script_text(soup: BeautifulSoup) -> str:
    return "\n".join(script.get_text(" ", strip=False) for script in soup.find_all("script"))


# Rule 1: literal IPv4/IPv6 hostnames, including common encoded IPv4 forms, are phishing.
@_fail_closed
def _ip_address_feature(url: str) -> int:
    return -1 if _parse_literal_ip(_hostname(url)) is not None else 1


# Rule 2: the published URL-length thresholds are <54, 54-75, and >75.
@_fail_closed
def _url_length_feature(url: str) -> int:
    return 1 if len(url) < 54 else 0 if len(url) <= 75 else -1


# Rule 3: known URL-shortener hostnames are suspicious.
@_fail_closed
def _shortening_feature(url: str) -> int:
    hostname = _hostname(url)
    shorteners = {
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
        "is.gd", "buff.ly", "adf.ly", "bit.do", "mcaf.ee",
    }
    return -1 if any(hostname == item or hostname.endswith("." + item) for item in shorteners) else 1


# Rule 4: an @ symbol anywhere in the URL indicates phishing.
@_fail_closed
def _at_symbol_feature(url: str) -> int:
    return -1 if "@" in url else 1


# Rule 5: a final // after index 7 indicates redirection embedded in the URL.
@_fail_closed
def _double_slash_feature(url: str) -> int:
    return -1 if url.rfind("//") > 7 else 1


# Rule 6: a hyphen in the URL's domain/netloc is suspicious.
@_fail_closed
def _prefix_suffix_feature(url: str) -> int:
    return -1 if "-" in urlparse(url).netloc else 1


# Rule 7: corrected tldextract-based subdomain counting, including multi-part TLDs.
@_fail_closed
def _subdomain_feature(url: str) -> int:
    extracted = _extractor()(_hostname(url))
    labels = [label for label in extracted.subdomain.split(".") if label and label.lower() != "www"]
    count = len(labels)
    return 1 if count == 0 else 0 if count == 1 else -1


# Rule 8: default OS trust roots are a current proxy for trusted certificate issuers;
# this deliberately simplifies the paper's three-way CA rule to trusted=1/untrusted=-1.
@_fail_closed
def _ssl_feature(url: str) -> int:
    """Return 1 only when HTTPS completes a trusted TLS handshake.

    The certificate-age check was removed because CA/Browser Forum Ballot
    SC-081v3, effective March 15, 2026, reduces maximum TLS certificate
    validity to 200 days (with further reductions scheduled), so a valid
    certificate cannot be 365 days old under current rules.
    """
    parsed, hostname = _parse_url(url)
    if parsed.scheme != "https":
        return -1
    addresses = resolve_and_validate_host(hostname)
    context = ssl.create_default_context()
    for address in addresses:
        try:
            with socket.create_connection((address, 443), timeout=10) as raw_socket:
                with context.wrap_socket(raw_socket, server_hostname=hostname):
                    return 1
        except (OSError, ssl.SSLError, KeyError, ValueError):
            continue
    return -1


# Rule 9: an expiry within 365 days, or a failed WHOIS lookup, is phishing.
@_fail_closed
def _registration_length_feature(url: str) -> int:
    record = _whois_record(_hostname(url))
    expiration = _date_value(getattr(record, "expiration_date", None))
    if expiration is None:
        return -1
    return -1 if expiration <= datetime.now(timezone.utc) + timedelta(days=365) else 1


# Rule 10: an off-domain favicon is phishing; same-domain or absent favicon is legitimate.
@_fail_closed
def _favicon_feature(url: str) -> int:
    _, soup, page_hostname = _page(url)
    for link in soup.find_all("link"):
        rel = {str(value).lower() for value in (link.get("rel") or [])}
        if "icon" in rel or {"shortcut", "icon"}.issubset(rel):
            href = link.get("href")
            if href and not _same_domain(urljoin(url, href), page_hostname):
                return -1
    return 1


# Rule 11: this interprets the paper's ambiguous port wording as exposed sensitive ports being risky.
@_fail_closed
def _port_feature(url: str) -> int:
    addresses = resolve_and_validate_host(_hostname(url))
    for address in addresses:
        for port in (21, 22, 23, 445, 1433, 1521, 3306, 3389):
            try:
                with socket.create_connection((address, port), timeout=1):
                    return -1
            except OSError:
                continue
    return 1


# Rule 12: the token https in the hostname/domain, excluding the scheme, is phishing.
@_fail_closed
def _https_token_feature(url: str) -> int:
    return -1 if "https" in _hostname(url) else 1


def _external_percentage(elements, attribute: str, page_url: str, page_hostname: str) -> float:
    values = [element.get(attribute) for element in elements if element.get(attribute) is not None]
    if not values:
        return 0.0
    external = sum(
        not _same_domain(urljoin(page_url, str(value)), page_hostname)
        for value in values
    )
    return external * 100 / len(values)


# Rule 13: external resource percentage thresholds are <22%, 22-61%, and >61%.
@_fail_closed
def _request_url_feature(url: str) -> int:
    _, soup, page_hostname = _page(url)
    tags = soup.find_all(["img", "audio", "embed", "iframe", "video", "source"])
    percentage = _external_percentage(tags, "src", url, page_hostname)
    return 1 if percentage < 22 else 0 if percentage <= 61 else -1


# Rule 14: off-domain or empty anchor percentage thresholds are <31%, 31-67%, and >67%.
@_fail_closed
def _anchor_feature(url: str) -> int:
    _, soup, page_hostname = _page(url)
    anchors = soup.find_all("a")
    if not anchors:
        return 1
    empty_values = {"", "#", "#content", "#skip", "javascript:void(0)"}
    off_domain = 0
    for anchor in anchors:
        href = (anchor.get("href") or "").strip()
        if href in empty_values or not _same_domain(urljoin(url, href), page_hostname):
            off_domain += 1
    percentage = off_domain * 100 / len(anchors)
    return 1 if percentage < 31 else 0 if percentage <= 67 else -1


# Rule 15: external meta/script/link percentage thresholds are <17%, 17-81%, and >81%.
@_fail_closed
def _links_in_tags_feature(url: str) -> int:
    _, soup, page_hostname = _page(url)
    elements = soup.find_all(["meta", "script", "link"])
    values = []
    for element in elements:
        for attribute in ("src", "href"):
            if element.get(attribute) is not None:
                values.append(element.get(attribute))
    if not values:
        return 1
    external = sum(
        not _same_domain(urljoin(url, str(value)), page_hostname) for value in values
    )
    percentage = external * 100 / len(values)
    return 1 if percentage < 17 else 0 if percentage <= 81 else -1


# Rule 16: empty/about:blank form actions are -1, off-domain actions are 0, otherwise 1.
@_fail_closed
def _sfh_feature(url: str) -> int:
    _, soup, page_hostname = _page(url)
    for form in soup.find_all("form"):
        action = form.get("action")
        if action == "" or action == "about:blank":
            return -1
        if action and not _same_domain(urljoin(url, action), page_hostname):
            return 0
    return 1


# Rule 17: mailto actions/links and inline mail( calls indicate phishing.
@_fail_closed
def _submitting_to_email_feature(url: str) -> int:
    _, soup, _ = _page(url)
    for element in soup.find_all(["form", "a"]):
        if "mailto:" in (element.get("action") or element.get("href") or "").lower():
            return -1
    if re.search(r"mail\s*\(", _static_script_text(soup), re.IGNORECASE):
        return -1
    return 1


# Rule 18: WHOIS identity presence approximates the original hostname identity rule.
@_fail_closed
def _abnormal_url_feature(url: str) -> int:
    record = _whois_record(_hostname(url))
    domain_name = getattr(record, "domain_name", None)
    registrant = getattr(record, "registrant_name", None) or getattr(
        record, "org", None
    )
    return 1 if domain_name or registrant else -1


# Rule 19: safe_get records the number of validated redirects actually followed.
@_fail_closed
def _redirect_feature(url: str) -> int:
    response = safe_get(url)
    hops = getattr(response, "_validated_redirect_hops", 0)
    return 1 if hops <= 1 else 0 if hops <= 3 else -1


# Rule 20: static approximation; dynamic/obfuscated JS is missed deliberately instead of executing
# untrusted JS server-side in a headless browser, which is outside this service's security scope.
@_fail_closed
def _mouseover_feature(url: str) -> int:
    response, soup, _ = _page(url)
    source = response.text + "\n" + _static_script_text(soup)
    match = re.search(
        r"onmouseover[\s\S]{0,200}(?:window\.status|status\s*=)|"
        r"(?:window\.status|status\s*=)[\s\S]{0,200}onmouseover",
        source,
        re.IGNORECASE,
    )
    return -1 if match else 1


# Rule 21: static approximation with the same deliberate limitation documented for onmouseover.
@_fail_closed
def _right_click_feature(url: str) -> int:
    _, soup, _ = _page(url)
    source = _static_script_text(soup)
    match = re.search(
        r"(?:event\.button\s*==\s*2|contextmenu)[\s\S]{0,200}preventDefault|"
        r"preventDefault[\s\S]{0,200}(?:event\.button\s*==\s*2|contextmenu)",
        source,
        re.IGNORECASE,
    )
    return -1 if match else 1


# Rule 22: static approximation with the same deliberate limitation documented for onmouseover.
@_fail_closed
def _popup_feature(url: str) -> int:
    _, soup, _ = _page(url)
    has_window_open = bool(re.search(r"window\.open\s*\(", _static_script_text(soup), re.IGNORECASE))
    return -1 if has_window_open and soup.find("input") is not None else 1


# Rule 23: iframe presence is fully reliable from the statically fetched HTML, unlike JS analysis.
@_fail_closed
def _iframe_feature(url: str) -> int:
    _, soup, _ = _page(url)
    return -1 if soup.find("iframe") is not None else 1


# Rule 24: a WHOIS creation age below 180 days, or failed WHOIS, is phishing.
@_fail_closed
def _age_of_domain_feature(url: str) -> int:
    record = _whois_record(_hostname(url))
    creation = _date_value(getattr(record, "creation_date", None))
    if creation is None:
        return -1
    return -1 if datetime.now(timezone.utc) - creation < timedelta(days=180) else 1


# Rule 25: DNSRecord checks whether any DNS resolution succeeds; private results remain informative here.
@_fail_closed
def _dns_record_feature(url: str) -> int:
    socket.getaddrinfo(_hostname(url), None)
    return 1


# Load the multi-million-row Tranco list once at module import, not once per prediction.
TRANCO_CACHE_DIR = Path(tempfile.gettempdir()) / "neuralsheild-tranco-cache"
TRANCO_LIST = Tranco(cache=True, cache_dir=str(TRANCO_CACHE_DIR)).list()


# Rule 26: Tranco rank <100000 is legitimate, unranked is phishing, and other ranks are suspicious.
@_fail_closed
def _web_traffic_feature(url: str) -> int:
    hostname = _hostname(url)
    extracted = tldextract.extract(hostname)
    # Reduce www/case/subdomains to the lowercase registrable domain Tranco ranks.
    registrable_domain = f"{extracted.domain}.{extracted.suffix}".lower()
    rank = TRANCO_LIST.rank(registrable_domain)
    return -1 if rank == -1 else 1 if rank < 100000 else 0


# Rule 27: OpenPageRank's 0-10 decimal score is normalized to 0-1 by dividing by 10.
@_fail_closed
def _page_rank_feature(url: str) -> int:
    if not OPENPAGERANK_API_KEY:
        return -1
    domain = _hostname(url)
    endpoint = "https://openpagerank.com/api/v1.0/getPageRank?domains[]=" + quote(domain)
    response = safe_get(endpoint, headers={"API-OPR": OPENPAGERANK_API_KEY})
    response.raise_for_status()
    payload = response.json()
    rows = payload.get("response", [])
    if not rows:
        return -1
    score = rows[0].get("page_rank_decimal")
    normalized = float(score) / 10
    return 1 if normalized >= 0.2 else -1


# Rule 28: Safe Browsing matches are phishing; API failure fails open because this is supplementary.
@_fail_closed
def _statistical_report_feature(url: str) -> int:
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return 1
    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="
        + quote(GOOGLE_SAFE_BROWSING_API_KEY, safe="")
    )
    body = {
        "client": {"clientId": "neuralsheild", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = _safe_api_post(endpoint, json=body)
        response.raise_for_status()
        return -1 if response.json().get("matches") else 1
    except Exception as exc:
        logger.debug("Safe Browsing lookup failed; using fail-open value: %s", exc)
        return 1


def extract_features(url: str) -> list[int]:
    """Return exactly 28 encoded features in the model's training-column order."""
    feature_functions = [
        _ip_address_feature,
        _url_length_feature,
        _shortening_feature,
        _at_symbol_feature,
        _double_slash_feature,
        _prefix_suffix_feature,
        _subdomain_feature,
        _ssl_feature,
        _registration_length_feature,
        _favicon_feature,
        _port_feature,
        _https_token_feature,
        _request_url_feature,
        _anchor_feature,
        _links_in_tags_feature,
        _sfh_feature,
        _submitting_to_email_feature,
        _abnormal_url_feature,
        _redirect_feature,
        _mouseover_feature,
        _right_click_feature,
        _popup_feature,
        _iframe_feature,
        _age_of_domain_feature,
        _dns_record_feature,
        _web_traffic_feature,
        _page_rank_feature,
        _statistical_report_feature,
    ]
    features = [function(url) for function in feature_functions]
    if len(features) != len(FEATURE_NAMES) or any(value not in {-1, 0, 1} for value in features):
        raise RuntimeError("Feature extraction did not produce the required 28-value encoding.")
    return features

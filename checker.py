"""
checker.py - Website Safety & Trust Signal Checker
==================================================
This module performs SAFE, PASSIVE checks on a target website URL.
It uses standard HTTP/HTTPS GET requests and parses the HTML using BeautifulSoup.

SAFETY GUARANTEE:
- No attacks, no exploits, no SQL injection, no XSS.
- Passive inspection only (normal web browsing behavior).
- Uses request timeouts to prevent freezing.
"""

import re
import socket
import time
import logging
import ssl
import copy
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)
MAX_HTML_BYTES = 500_000
CACHE_TTL_SECONDS = 300
_scan_cache: dict[str, tuple[float, dict]] = {}
_cache_lock = threading.Lock()
MAX_REDIRECTS = 5

# A standard browser User-Agent so target websites don't reject requests
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36 WebTrust-Scanner/1.0"
    )
}

# Suspicious keywords commonly used in phishing or scam URLs
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "banking", "secure", "account",
    "free", "bonus", "crypto", "signin", "wallet", "support",
    "password", "auth", "confirm", "claim"
]

URGENCY_PHRASES = (
    "account suspended", "verify immediately", "act now", "limited time",
    "your account will be closed", "urgent action", "confirm within",
)
SUPPORT_SCAM_PHRASES = (
    "call support", "contact support immediately", "toll free", "microsoft support",
    "apple support", "virus detected", "computer infected",
)
KNOWN_BRANDS = ("paypal", "microsoft", "apple", "amazon", "google", "netflix", "coinbase")


class SSRFBlockedError(ValueError):
    """Raised when a scan target resolves to a non-public network address."""


def _is_public_ip(address: str) -> bool:
    """Allow only globally routable IP addresses for outbound scans."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return parsed.is_global


def validate_scan_target(url: str) -> None:
    """
    Validate a URL before the server makes an outbound request.

    This blocks localhost, private, loopback, link-local, multicast, reserved,
    and otherwise non-public destinations, including redirect targets.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if parsed.scheme not in {"http", "https"} or not hostname:
        raise SSRFBlockedError("Only HTTP and HTTPS public website URLs can be scanned.")

    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise SSRFBlockedError(
            f"The scan target could not be resolved safely: {hostname}."
        ) from exc

    if not addresses or not all(_is_public_ip(address) for address in addresses):
        raise SSRFBlockedError(
            "Scanning private, local, reserved, or otherwise non-public network "
            "addresses is blocked."
        )


def validate_redirect(response: requests.Response, *args: Any, **kwargs: Any) -> requests.Response:
    """Reject a redirect before Requests follows it."""
    if len(response.history) >= MAX_REDIRECTS:
        raise SSRFBlockedError(
            f"Redirect chain exceeded the limit of {MAX_REDIRECTS} hops."
        )
    location = response.headers.get("Location")
    if location:
        redirect_url = urljoin(response.url, location)
        validate_scan_target(redirect_url)
    return response


def is_ip_address(domain: str) -> bool:
    """
    Check if a domain name is a raw IPv4 or IPv6 address instead of a domain name.
    Legitimate public websites rarely use direct IP addresses.
    """
    # Remove port if present (e.g. 192.168.1.1:8080)
    host = domain.split(":")[0]
    
    # Try IPv4
    try:
        socket.inet_aton(host)
        return True
    except socket.error:
        pass

    # Try IPv6
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except (socket.error, AttributeError):
        pass

    return False


def normalize_url(url: str) -> str:
    """
    Ensure the URL has a valid scheme (defaults to https:// if missing).
    Cleans leading/trailing whitespace.
    """
    if not isinstance(url, str):
        raise ValueError("URL must be text.")
    url = url.strip()
    if not url:
        raise ValueError("URL cannot be empty.")
    if any(char.isspace() for char in url):
        raise ValueError("URL cannot contain spaces.")
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Please enter a valid HTTP or HTTPS website address.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing usernames or passwords are not supported.")
    return parsed._replace(scheme=parsed.scheme.lower()).geturl()


def analyze_url_structure(url: str) -> dict:
    """
    Examines the URL string itself for structural anomalies and risk indicators.
    Does not require an internet connection.
    """
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    
    # Subdomain count: count dots in the hostname, ignoring trailing dot
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    # Example: "sub.example.com" has 3 parts -> 1 subdomain
    # "a.b.c.example.com" has 5 parts -> 3 subdomains
    subdomain_count = max(0, len(parts) - 2)
    
    # Check for IP address in host
    is_ip = is_ip_address(hostname)
    
    # Check URL length (URLs over 75 characters are statistically more common in phishing)
    url_length = len(url)
    is_long_url = url_length > 75
    
    # Check for suspicious characters
    has_at_symbol = "@" in url  # @ can be used to trick URL parsers (e.g., legitimate.com@evil.com)
    excessive_hyphens = domain.count("-") >= 3
    excessive_subdomains = subdomain_count >= 3
    
    # Check for suspicious keywords in domain or path
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path or kw in domain]
    
    return {
        "url": url,
        "scheme": parsed.scheme,
        "domain": hostname,
        "is_https": parsed.scheme == "https",
        "url_length": url_length,
        "is_long_url": is_long_url,
        "is_ip_address": is_ip,
        "subdomain_count": subdomain_count,
        "excessive_subdomains": excessive_subdomains,
        "has_at_symbol": has_at_symbol,
        "excessive_hyphens": excessive_hyphens,
        "found_keywords": found_keywords,
        "is_valid": bool(parsed.hostname and parsed.scheme in {"http", "https"}),
    }


def check_trust_pages(soup: BeautifulSoup) -> tuple[dict, dict]:
    """
    Passively scans the page's <a> tags to see if common trust pages exist:
    - About Us
    - Contact Us
    - Privacy Policy
    - Terms of Service
    - Refund / Return Policy
    """
    # Match meaningful labels and URL path segments, rather than arbitrary
    # substrings such as "support" in an unrelated help link.
    targets = {
        "about": {"about", "about-us", "who-we-are", "our-story"},
        "contact": {"contact", "contact-us", "reach-us", "get-in-touch"},
        "privacy": {"privacy", "privacy-policy", "data-protection"},
        "terms": {"terms", "tos", "conditions", "terms-of-service", "terms-of-use"},
        "refund": {"refund", "return", "returns", "cancellation", "returns-policy"}
    }
    
    results = {
        "about": False,
        "contact": False,
        "privacy": False,
        "terms": False,
        "refund": False
    }
    evidence = {key: [] for key in targets}

    if not soup:
        return results, evidence

    def matching_target(value: str, keywords: set) -> bool:
        normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
        tokens = set(normalized.split("-"))
        return normalized in keywords or bool(tokens.intersection(keywords))

    # Check links and visible headings. Evidence is retained for explainable
    # scoring and lets callers distinguish a label from a URL match.
    for a in soup.find_all("a", href=True):
        href = str(a.get("href") or "").lower()
        text = a.get_text(" ", strip=True).lower()
        path = urlparse(href).path
        
        for key, keywords in targets.items():
            if not results[key]:
                if matching_target(text, keywords) or any(
                    matching_target(part, keywords)
                    for part in path.split("/")
                    if part
                ):
                    results[key] = True
                    evidence[key].append({"text": text[:100], "href": href[:200]})

    for heading in soup.find_all(["h1", "h2", "h3", "nav", "footer"]):
        text = heading.get_text(" ", strip=True).lower()
        for key, keywords in targets.items():
            if not results[key] and matching_target(text, keywords):
                results[key] = True
                evidence[key].append({"text": text[:100], "href": None})

    return results, evidence


def check_security_headers(headers: Mapping[str, str]) -> dict:
    """
    Checks for the presence of standard HTTP security headers that protect
    browsers from common web threats (like clickjacking, MIME sniffing, and MITM).
    """
    # Convert header keys to lowercase for case-insensitive lookup
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    return {
        "hsts": "strict-transport-security" in headers_lower,
        "csp": "content-security-policy" in headers_lower,
        "x_frame_options": "x-frame-options" in headers_lower,
        "x_content_type_options": "x-content-type-options" in headers_lower,
        "referrer_policy": "referrer-policy" in headers_lower,
    }


def analyze_content_signals(soup: BeautifulSoup, hostname: str, title: str) -> dict:
    """Extract passive content heuristics with evidence for explainable scoring."""
    visible_text = soup.get_text(" ", strip=True).lower()[:200000]
    title_text = title.lower()
    urgency = [phrase for phrase in URGENCY_PHRASES if phrase in visible_text]
    support = [phrase for phrase in SUPPORT_SCAM_PHRASES if phrase in visible_text]
    password_inputs = soup.find_all("input", {"type": "password"})
    login_forms = [
        form for form in soup.find_all("form")
        if form.find("input", {"type": "password"})
        or any(term in form.get_text(" ", strip=True).lower() for term in ("login", "sign in", "password"))
    ]
    external_form_actions = []
    for form in soup.find_all("form", action=True):
        action = str(form.get("action") or "").strip()
        parsed_action = urlparse(action)
        if parsed_action.hostname and parsed_action.hostname.lower() != hostname.lower():
            external_form_actions.append(action[:200])

    brand_mentions = [
        brand for brand in KNOWN_BRANDS
        if brand in visible_text or brand in title_text
    ]
    brand_mismatch = [
        brand for brand in brand_mentions
        if brand not in hostname.lower()
    ]
    return {
        "urgency_phrases": urgency,
        "support_scam_phrases": support,
        "login_form_count": len(login_forms),
        "password_field_count": len(password_inputs),
        "external_form_actions": external_form_actions,
        "brand_mentions": brand_mentions,
        "brand_mismatch": brand_mismatch,
        "text_length": len(visible_text),
    }


def inspect_tls_certificate(hostname: str, port: int = 443) -> dict:
    """Inspect the public TLS certificate without disabling verification."""
    result = {
        "checked": False,
        "valid": None,
        "issuer": None,
        "subject": None,
        "expires_at": None,
        "days_until_expiry": None,
        "error": None,
    }
    context = ssl.create_default_context()

    def certificate_value(certificate: dict[str, Any], section: str, name: str) -> str | None:
        entries = certificate.get(section)
        if not isinstance(entries, tuple):
            return None
        for entry in entries:
            if isinstance(entry, tuple) and len(entry) == 2 and entry[0] == name:
                return str(entry[1])
        return None

    try:
        with socket.create_connection((hostname, port), timeout=5) as connection:
            with context.wrap_socket(connection, server_hostname=hostname) as tls_socket:
                raw_certificate = tls_socket.getpeercert()
                if not raw_certificate:
                    raise ValueError("Certificate details are unavailable.")
                certificate: dict[str, Any] = dict(raw_certificate)
        not_after = certificate.get("notAfter")
        if not isinstance(not_after, str):
            raise ValueError("Certificate expiry is unavailable.")
        expires_at = datetime.strptime(
            not_after, "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)
        result.update({
            "checked": True,
            "valid": True,
            "issuer": certificate_value(certificate, "issuer", "organizationName"),
            "subject": certificate_value(certificate, "subject", "commonName"),
            "expires_at": expires_at.isoformat(),
            "days_until_expiry": (expires_at - datetime.now(timezone.utc)).days,
        })
    except (ssl.SSLError, OSError, KeyError, ValueError) as exc:
        result["checked"] = True
        result["valid"] = False
        result["error"] = str(exc)
    return result


def inspect_dns(hostname: str) -> dict:
    """Collect DNS resolution and optional MX evidence."""
    result = {
        "resolved": False,
        "addresses": [],
        "mx_records": [],
        "error": None,
    }
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        }
        result["addresses"] = sorted(addresses)
        result["resolved"] = bool(result["addresses"])
    except socket.gaierror as exc:
        result["error"] = str(exc)

    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        return result
    try:
        result["mx_records"] = sorted(
            str(getattr(answer, "exchange", "")).rstrip(".")
            for answer in dns.resolver.resolve(hostname, "MX", lifetime=5)
        )
    except (dns.exception.DNSException, OSError):
        # MX data is supplementary; a resolver/library failure does not make
        # the primary website scan fail.
        pass
    return result


def inspect_whois(hostname: str) -> dict:
    """Collect registration dates when python-whois is available."""
    result = {
        "available": False,
        "created_at": None,
        "expires_at": None,
        "domain_age_days": None,
        "error": None,
    }
    try:
        import whois
        record = whois.whois(hostname)
        result["available"] = True
        created = record.creation_date
        expires = record.expiration_date
        if isinstance(created, list):
            created = min(created)
        if isinstance(expires, list):
            expires = max(expires)
        if isinstance(created, datetime):
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            result["created_at"] = created.isoformat()
            result["domain_age_days"] = max(
                0, (datetime.now(timezone.utc) - created).days
            )
        if isinstance(expires, datetime):
            result["expires_at"] = expires.isoformat()
    except (ImportError, OSError, ValueError, AttributeError) as exc:
        result["error"] = str(exc)
    return result


def inspect_whois_with_timeout(hostname: str, timeout: float = 5) -> dict:
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(inspect_whois, hostname)
    try:
        return future.result(timeout=timeout)
    except TimeoutError:
        future.cancel()
        return {
            "available": False,
            "created_at": None,
            "expires_at": None,
            "domain_age_days": None,
            "error": "WHOIS lookup timed out.",
        }
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def analyze_website(target_url: str) -> dict:
    """
    Main passive analysis function.
    
    Steps:
    1. Clean and parse URL structure
    2. Perform a safe HTTP GET request with a 6-second timeout
    3. Measure response status and latency
    4. Parse HTML with BeautifulSoup for links, forms, title, and trust pages
    5. Check security headers
    
    Returns a comprehensive dictionary containing all collected signals.
    """
    try:
        cleaned_url = normalize_url(target_url)
        url_data = analyze_url_structure(cleaned_url)
    except ValueError as exc:
        return {
            "success": False,
            "error_type": "invalid_url",
            "error_message": str(exc),
            "url_data": {
                "url": str(target_url or "").strip(),
                "domain": "",
                "scheme": "",
                "is_https": False,
                "is_valid": False,
            },
            "status_code": None,
            "response_time": 0.0,
            "redirect_count": 0,
            "redirect_history": [],
            "redirect_chain": [],
            "original_url": str(target_url or "").strip(),
            "final_url": None,
            "title": "N/A",
            "link_count": 0,
            "form_count": 0,
            "has_password_field": False,
            "content_signals": {},
            "security_headers": {},
            "trust_pages": {key: False for key in ("about", "contact", "privacy", "terms", "refund")},
            "trust_page_evidence": {},
            "server_info": "Unknown",
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    now = time.time()
    with _cache_lock:
        cached = _scan_cache.get(cleaned_url)
        if cached and now - cached[0] < CACHE_TTL_SECONDS:
            cached_result = copy.deepcopy(cached[1])
            cached_result["cache_hit"] = True
            cached_result["scan_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
            logger.info("Cache hit for %s", cleaned_url)
            return cached_result
        if cached:
            del _scan_cache[cleaned_url]
    
    # Default structure in case of request error
    result = {
        "success": False,
        "error_message": None,
        "error_type": None,
        "url_data": url_data,
        "status_code": None,
        "response_time": 0.0,
        "redirect_count": 0,
        "redirect_history": [],
        "redirect_chain": [],
        "original_url": cleaned_url,
        "final_url": None,
        "title": "N/A",
        "link_count": 0,
        "form_count": 0,
        "has_password_field": False,
        "content_signals": {},
        "security_headers": {
            "hsts": False,
            "csp": False,
            "x_frame_options": False,
            "x_content_type_options": False,
            "referrer_policy": False
        },
        "tls_certificate": {
            "checked": False,
            "valid": None,
            "issuer": None,
            "subject": None,
            "expires_at": None,
            "days_until_expiry": None,
            "error": None,
        },
        "dns": {"resolved": False, "addresses": [], "mx_records": [], "error": None},
        "whois": {
            "available": False,
            "created_at": None,
            "expires_at": None,
            "domain_age_days": None,
            "error": None,
        },
        "trust_pages": {
            "about": False,
            "contact": False,
            "privacy": False,
            "terms": False,
            "refund": False
        },
        "trust_page_evidence": {},
        "server_info": "Unknown",
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "cache_hit": False,
    }

    # Validate domain before sending network request
    if not url_data["domain"] or not url_data.get("is_valid"):
        result["error_message"] = "Invalid URL format. Please enter a valid website address."
        result["error_type"] = "invalid_url"
        return result

    try:
        validate_scan_target(cleaned_url)
    except SSRFBlockedError as exc:
        result["error_type"] = "ssrf_blocked"
        result["error_message"] = str(exc)
        logger.warning("Blocked unsafe scan target url=%s reason=%s", cleaned_url, exc)
        return result

    result["dns"] = inspect_dns(url_data["domain"])
    result["whois"] = inspect_whois_with_timeout(url_data["domain"])
    if url_data.get("is_https") and not url_data.get("is_ip_address"):
        result["tls_certificate"] = inspect_tls_certificate(url_data["domain"])

    # Perform safe HTTP request
    response = None
    try:
        start_time = time.time()
        response = requests.get(
            cleaned_url,
            headers=DEFAULT_HEADERS,
            timeout=(3, 7),          # Separate connect/read limits prevent hanging scans
            allow_redirects=True,    # Follow redirects to see where it leads
            hooks={"response": [validate_redirect]},
            stream=True
        )
        elapsed = round(time.time() - start_time, 2)
        
        result["success"] = True
        result["status_code"] = response.status_code
        result["response_time"] = elapsed
        result["redirect_count"] = len(response.history)
        result["redirect_history"] = [r.url for r in response.history] + [response.url]
        result["final_url"] = response.url
        result["redirect_chain"] = [
            {
                "url": item.url,
                "status_code": item.status_code,
                "location": item.headers.get("Location"),
            }
            for item in response.history
        ] + [{
            "url": response.url,
            "status_code": response.status_code,
            "location": None,
        }]
        result["server_info"] = response.headers.get("Server", "Hidden / Not Disclosed")
        
        # Check security headers on final response
        result["security_headers"] = check_security_headers(response.headers)
        
        # Read only a bounded prefix instead of buffering an untrusted full response.
        body = bytearray()
        for chunk in response.iter_content(chunk_size=16_384):
            if not chunk:
                continue
            remaining = MAX_HTML_BYTES - len(body)
            body.extend(chunk[:remaining])
            if len(body) >= MAX_HTML_BYTES:
                break
        html_content = bytes(body).decode(response.encoding or "utf-8", errors="replace")
        soup = BeautifulSoup(html_content, "html.parser")
        
        # Extract title
        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            result["title"] = title_tag.string.strip()[:100]  # Truncate if excessively long
        else:
            result["title"] = "No Title Found"
            
        # Count links
        links = soup.find_all("a")
        result["link_count"] = len(links)
        
        # Count forms & check for password inputs
        forms = soup.find_all("form")
        result["form_count"] = len(forms)
        password_inputs = soup.find_all("input", {"type": "password"})
        result["has_password_field"] = len(password_inputs) > 0
        
        # Check for trust pages
        result["trust_pages"], result["trust_page_evidence"] = check_trust_pages(soup)
        result["content_signals"] = analyze_content_signals(
            soup, url_data["domain"], result["title"]
        )
        with _cache_lock:
            if len(_scan_cache) >= 256:
                oldest_url = min(_scan_cache, key=lambda key: _scan_cache[key][0])
                del _scan_cache[oldest_url]
            _scan_cache[cleaned_url] = (time.time(), copy.deepcopy(result))
        logger.info(
            "Scan completed url=%s status=%s redirects=%s bytes=%s",
            cleaned_url, response.status_code, result["redirect_count"], len(body)
        )
        
    except SSRFBlockedError as exc:
        result["error_type"] = "ssrf_blocked"
        result["error_message"] = str(exc)
        logger.warning("Blocked unsafe redirect while scanning %s: %s", cleaned_url, exc)
    except requests.exceptions.SSLError:
        result["error_type"] = "ssl"
        result["error_message"] = "SSL/HTTPS Certificate Error. The website's security certificate is invalid, expired, or self-signed."
    except requests.exceptions.Timeout:
        result["error_type"] = "timeout"
        result["error_message"] = "Connection Timed Out. The website took more than 7 seconds to respond."
    except requests.exceptions.ConnectionError:
        result["error_type"] = "connection"
        result["error_message"] = "Connection Failed. Could not reach the server. Domain may not exist or the server is down."
    except requests.exceptions.RequestException as e:
        result["error_type"] = "request"
        result["error_message"] = f"Network Request Error: {str(e)}"
    except Exception as e:
        result["error_type"] = "unexpected"
        result["error_message"] = f"Unexpected Error: {str(e)}"
        logger.exception("Unexpected error while scanning %s", cleaned_url)
    finally:
        if response is not None:
            response.close()

    return result

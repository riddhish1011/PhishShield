"""PhishShield scan API for Vercel (Python serverless function).

POST /api/scan   body: {"url": "https://example.com"}  ->  scan result JSON
GET  /api/scan   -> {"ok": true, "google_configured": bool}

The URL is only analysed as a string. This function never opens the site.
Optional environment variables (Vercel -> Settings -> Environment Variables):
  GOOGLE_SAFE_BROWSING_API_KEY   enables the Safe Browsing lookup
  TRUSTED_HOSTS                  comma-separated exact hosts to trust
"""

import ipaddress
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse

GOOGLE_API_ENDPOINT = "https://safebrowsing.googleapis.com/v5/urls:search"

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "rb.gy", "shorturl.at", "ow.ly",
    "buff.ly", "rebrand.ly", "soo.gd",
}

SUSPICIOUS_WORDS = {
    "login", "signin", "verify", "verification",
    "account", "password", "credential", "secure",
    "update", "confirm", "wallet", "banking",
    "payment", "invoice", "recover", "unlock",
    "suspended", "gift", "prize", "free",
}

SUSPICIOUS_EXTENSIONS = (
    ".exe", ".scr", ".bat", ".cmd", ".msi",
    ".js", ".vbs", ".ps1", ".apk",
)

SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "work", "country",
    "gq", "tk", "top", "xyz", "support",
}

# Exact hosts only (no subdomains). Your own deployed host is added
# automatically from the request headers and Vercel's environment.
TRUSTED_EXACT = {"localhost", "127.0.0.1"}

# These domains and all their subdomains are trusted.
TRUSTED_DOMAINS = {"google.com", "github.com", "microsoft.com", "gla.ac.in"}


# ----------------------------------------------------------------------
# URL helpers
# ----------------------------------------------------------------------

def normalize_url(raw_url):
    value = str(raw_url or "").strip()

    if not value:
        raise ValueError("Enter a URL to scan.")
    if any(ord(ch) < 32 for ch in value):
        raise ValueError("The URL contains invalid control characters.")
    if len(value) > 4096:
        raise ValueError("The URL is too long to scan.")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value

    parsed = urlparse(value)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname:
        raise ValueError("Enter a valid URL containing a hostname.")

    try:
        _ = parsed.port
    except ValueError:
        raise ValueError("The URL contains an invalid port.")

    return value, parsed


def host_is_ip_address(host):
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def extract_features(raw_url):
    normalized, parsed = normalize_url(raw_url)

    host = (parsed.hostname or "").lower().rstrip(".")
    path = parsed.path or "/"
    host_parts = [p for p in host.split(".") if p]

    try:
        port = parsed.port
    except ValueError:
        port = None

    is_ip = host_is_ip_address(host)
    tld = host_parts[-1] if host_parts else ""
    url_lower = normalized.lower()

    matched_words = sorted({
        word for word in SUSPICIOUS_WORDS
        if re.search(r"(?<![a-z0-9])" + re.escape(word) + r"(?![a-z0-9])", url_lower)
    })

    has_userinfo = parsed.username is not None

    features = {
        "url_length": len(normalized),
        "host_length": len(host),
        "path_length": len(path),
        "dot_count": host.count("."),
        "hyphen_count": host.count("-"),
        "at_count": normalized.count("@"),
        "digit_count": sum(c.isdigit() for c in normalized),
        "subdomain_count": max(0, len(host_parts) - 2),
        "has_https": int(parsed.scheme.lower() == "https"),
        "host_is_ip": int(is_ip),
        "has_punycode": int("xn--" in host),
        "is_shortener": int(host in SHORTENERS),
        "has_suspicious_word": int(bool(matched_words)),
        "has_suspicious_extension": int(
            any(path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)
        ),
        "has_suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "has_port": int(port is not None and port not in {80, 443}),
        "percent_count": normalized.count("%"),
        "has_userinfo": int(has_userinfo),
        "has_query": int(bool(parsed.query)),
    }

    details = {
        "normalized_url": normalized,
        "host": host,
        "matched_words": matched_words,
        "has_userinfo": has_userinfo,
    }
    return features, details


# ----------------------------------------------------------------------
# Trusted hosts
# ----------------------------------------------------------------------

def _clean_host(value):
    value = (value or "").split(",")[0].strip().lower()
    if not value:
        return ""
    value = re.sub(r"^https?://", "", value).split("/")[0]
    if value.startswith("["):
        return value.split("]")[0].strip("[]")
    return value.split(":")[0].rstrip(".")


def trusted_exact_hosts(own_host):
    hosts = set(TRUSTED_EXACT)
    hosts.update(
        _clean_host(h) for h in os.environ.get("TRUSTED_HOSTS", "").split(",") if h.strip()
    )
    for var in ("VERCEL_URL", "VERCEL_BRANCH_URL", "VERCEL_PROJECT_PRODUCTION_URL"):
        host = _clean_host(os.environ.get(var, ""))
        if host:
            hosts.add(host)
    if own_host:
        hosts.add(own_host)
    hosts.discard("")
    return hosts


def trust_reason(host, own_host):
    host = (host or "").lower().rstrip(".")
    if not host:
        return None

    if host in trusted_exact_hosts(own_host):
        if own_host and host == own_host:
            return "This is the PhishShield website itself (same host as this app)."
        return "This host is on the trusted-host list."

    for domain in TRUSTED_DOMAINS:
        if host == domain or host.endswith("." + domain):
            return "This host belongs to the trusted domain " + domain + "."
    return None


# ----------------------------------------------------------------------
# Heuristic scoring
# ----------------------------------------------------------------------

def heuristic_scan(raw_url, own_host):
    features, details = extract_features(raw_url)

    state = {"score": 0}
    reasons = []

    def add(points, message):
        state["score"] += points
        reasons.append(message)

    if features["host_is_ip"]:
        add(3, "The hostname is an IP address rather than a domain name.")
    if features["has_punycode"]:
        add(2, "The hostname uses punycode encoding; inspect for lookalike domains.")
    if details["has_userinfo"]:
        add(3, "The URL contains user-information syntax before the hostname.")
    if features["is_shortener"]:
        add(1, "The URL uses a known link-shortening service, which hides its destination.")

    if features["subdomain_count"] >= 4:
        add(2, "The hostname has an unusually large number of subdomains.")
    elif features["subdomain_count"] >= 2:
        add(1, "The hostname contains multiple subdomains.")

    if features["hyphen_count"] >= 4:
        add(2, "The URL contains many hyphens.")
    elif features["hyphen_count"] >= 2:
        add(1, "The URL contains multiple hyphens.")

    if features["url_length"] > 180:
        add(2, "The URL is unusually long.")
    elif features["url_length"] > 100:
        add(1, "The URL is relatively long.")

    if features["has_suspicious_word"]:
        words = ", ".join(details["matched_words"][:6])
        add(2, "Potentially sensitive wording appears in the URL: " + words + ".")

    if features["has_suspicious_extension"]:
        add(3, "The path ends with a potentially risky executable or script extension.")
    if features["has_suspicious_tld"]:
        add(1, "The top-level domain is on a heuristic watchlist; this alone proves nothing.")
    if features["has_port"]:
        add(1, "The URL specifies a non-standard web port.")

    if features["percent_count"] >= 5:
        add(2, "The URL contains extensive percent-encoding.")
    elif features["percent_count"] >= 2:
        add(1, "The URL contains repeated percent-encoding.")

    if features["at_count"] > 0 and not details["has_userinfo"]:
        add(1, "The URL contains an @ character that merits inspection.")

    if not features["has_https"]:
        add(1, "The URL does not use HTTPS.")

    score = min(10, state["score"])

    trusted = False
    reason = trust_reason(details["host"], own_host)
    if reason:
        hard_flags = (
            features["has_userinfo"]
            or features["has_suspicious_extension"]
            or features["has_punycode"]
        )
        if not hard_flags:
            trusted = True
            score = 0
            reasons = [reason]

    if not reasons:
        reasons.append("No listed heuristic warning was triggered.")

    return {
        "score": score,
        "reasons": reasons,
        "features": features,
        "details": details,
        "trusted": trusted,
    }


def level_for(score):
    if score <= 3:
        return "Low"
    if score <= 6:
        return "Medium"
    return "High"


# ----------------------------------------------------------------------
# Google Safe Browsing (never reports an API error as "safe")
# ----------------------------------------------------------------------

def google_configured():
    return bool(os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip())


def google_safe_browsing_check(url):
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

    if not api_key:
        return {
            "status": "Not configured",
            "threat_types": [],
            "message": "Google Safe Browsing API key is not configured.",
        }

    query = urllib.parse.urlencode({"key": api_key, "urls": url})
    request = urllib.request.Request(GOOGLE_API_ENDPOINT + "?" + query)

    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return {
            "status": "Unavailable",
            "threat_types": [],
            "message": (
                "Google API returned HTTP " + str(exc.code) + ". "
                "Check API setup, permissions, quota, and endpoint availability."
            ),
        }
    except (urllib.error.URLError, TimeoutError):
        return {
            "status": "Unavailable",
            "threat_types": [],
            "message": "Could not connect to Google Safe Browsing.",
        }
    except (ValueError, UnicodeDecodeError):
        return {
            "status": "Unavailable",
            "threat_types": [],
            "message": "The API response could not be interpreted.",
        }

    threats = payload.get("threats", [])
    if threats:
        threat_types = sorted({
            t for threat in threats for t in threat.get("threatTypes", [])
        })
        return {
            "status": "Known threat",
            "threat_types": threat_types,
            "message": "Google Safe Browsing reported a threat match.",
        }

    return {
        "status": "No known threat found",
        "threat_types": [],
        "message": (
            "No match was returned by the threat list. "
            "This does not guarantee the URL is safe."
        ),
    }


# ----------------------------------------------------------------------
# Full scan
# ----------------------------------------------------------------------

def run_scan(raw_url, own_host=""):
    heuristic = heuristic_scan(raw_url, own_host)
    normalized_url = heuristic["details"]["normalized_url"]
    trusted = heuristic["trusted"]

    google = google_safe_browsing_check(normalized_url)

    score = heuristic["score"]
    reasons = list(heuristic["reasons"])

    # A known-threat match overrides everything, even the trusted list.
    if google["status"] == "Known threat":
        score = 10
        trusted = False
        reasons.insert(0, "Google Safe Browsing returned a known-threat match.")

    level = level_for(score)

    if google["status"] == "Known threat":
        verdict = "Known malicious URL"
    elif trusted:
        verdict = "Trusted host; no risk indicators"
    elif level == "High":
        verdict = "High-risk URL"
    elif level == "Medium":
        verdict = "Suspicious URL"
    elif google["status"] == "No known threat found":
        verdict = "No known threat found; low heuristic risk"
    else:
        verdict = "Low heuristic risk; external check unavailable"

    seen = set()
    unique_reasons = []
    for reason in reasons:
        if reason not in seen:
            seen.add(reason)
            unique_reasons.append(reason)

    return {
        "url": normalized_url,
        "score": score,
        "level": level,
        "verdict": verdict,
        "trusted": trusted,
        "reasons": unique_reasons,
        "google": google,
        "features": heuristic["features"],
    }


# ----------------------------------------------------------------------
# Vercel entry point
# ----------------------------------------------------------------------

class handler(BaseHTTPRequestHandler):
    def _send(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(200, {"ok": True, "google_configured": google_configured()})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0

        if length <= 0 or length > 16384:
            self._send(400, {"error": "Send a JSON body with a url field."})
            return

        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
            raw_url = data.get("url", "") if isinstance(data, dict) else ""
        except (ValueError, UnicodeDecodeError):
            self._send(400, {"error": "The request body must be valid JSON."})
            return

        own_host = _clean_host(
            self.headers.get("x-forwarded-host") or self.headers.get("host") or ""
        )

        try:
            self._send(200, run_scan(raw_url, own_host))
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except Exception:
            self._send(500, {"error": "Scan could not be completed."})

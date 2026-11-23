import math
import re
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
import tldextract
from app.schemas.analysis import LexicalDNA, IdentityDNA

# Common brands heavily targeted by phishing campaigns
TARGETED_BRANDS = {
    "paypal": ["paypal.com", "paypal.me"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "office365.com", "azure.com", "windows.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com", "accounts.google.com"],
    "netflix": ["netflix.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "dropbox": ["dropbox.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "whatsapp": ["whatsapp.com"],
    "telegram": ["telegram.org", "t.me"]
}

# TLDs historically associated with high phishing abuse or free registration
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "work", "icu",
    "country", "stream", "kim", "racing", "fit", "surf", "monster", "cfd"
}

# Known URL shortener services
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy"
}

# Keywords frequently appearing in phishing credential harvesters
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "account", "update", "banking", "secure", "security", "wallet",
    "recover", "recovery", "authenticate", "auth", "confirm", "confirmation",
    "credential", "password", "reset", "webscr", "identity"
]

IPV4_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return round(-sum(p * math.log2(p) for p in prob), 3)


def normalize_url(raw_url: str) -> str:
    """Ensures raw URL has a valid scheme for robust parsing."""
    url = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def analyze_url_heuristics(raw_url: str) -> Dict[str, Any]:
    """
    Performs comprehensive heuristic, lexical, identity, and structural analysis
    on a suspect URL (FR-01, Section 8).
    """
    normalized = normalize_url(raw_url)
    parsed = urlparse(normalized)
    
    extracted = tldextract.extract(normalized)
    # Extract domain components cleanly
    subdomain = extracted.subdomain.lower()
    domain = extracted.domain.lower()
    suffix = extracted.suffix.lower()
    if hasattr(extracted, "top_domain_under_public_suffix"):
        registered_domain = (extracted.top_domain_under_public_suffix or "").lower()
    else:
        registered_domain = (extracted.registered_domain or "").lower()
    host = parsed.netloc.split(":")[0].lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    indicators: List[Dict[str, Any]] = []
    limitations: List[str] = []
    evidence: Dict[str, Any] = {}

    # 1. Lexical DNA
    subdomain_parts = [p for p in subdomain.split(".") if p] if subdomain else []
    subdomain_count = len(subdomain_parts)
    hyphen_count = host.count("-")
    is_ip = bool(IPV4_PATTERN.match(host))
    is_shortener = host in URL_SHORTENERS or registered_domain in URL_SHORTENERS
    suspicious_tld = suffix in SUSPICIOUS_TLDS
    domain_entropy = calculate_entropy(domain)

    lexical_dna = LexicalDNA(
        url_length=len(normalized),
        domain_length=len(registered_domain or host),
        subdomain_count=subdomain_count,
        hyphen_count=hyphen_count,
        has_ip_address=is_ip,
        is_shortener=is_shortener,
        suspicious_tld=suspicious_tld,
        entropy=domain_entropy
    )

    evidence["normalized_url"] = normalized
    evidence["registered_domain"] = registered_domain or host
    evidence["domain_entropy"] = domain_entropy
    evidence["has_ip_host"] = is_ip
    evidence["url_shortener"] = is_shortener

    # Flag: IP Address used as host
    if is_ip:
        indicators.append({
            "type": "LEXICAL",
            "severity": "HIGH",
            "title": "IP Address Used Directly as Host",
            "description": f"The URL host '{host}' is a raw IP address instead of a registered domain, commonly used in phishing campaigns to bypass domain reputation checks.",
            "source": "LOCAL_HEURISTICS"
        })

    # Flag: URL Shortener
    if is_shortener:
        indicators.append({
            "type": "LEXICAL",
            "severity": "MEDIUM",
            "title": "URL Shortener Cloaking Destination",
            "description": f"The host '{host}' is a URL shortening service that masks the real destination endpoint and redirects users.",
            "source": "LOCAL_HEURISTICS"
        })
        limitations.append(
            "Target uses a URL shortener; destination page redirects were not dynamically resolved without active web crawl."
        )

    # Flag: Suspicious/Abused TLD
    if suspicious_tld:
        indicators.append({
            "type": "LEXICAL",
            "severity": "HIGH",
            "title": f"High-Risk Top-Level Domain (.{suffix})",
            "description": f"The top-level domain '.{suffix}' exhibits statistically high rates of phishing and malicious abuse.",
            "source": "LOCAL_HEURISTICS"
        })

    # Flag: Excessive length
    if len(normalized) > 100:
        indicators.append({
            "type": "LEXICAL",
            "severity": "LOW",
            "title": "Excessively Long URL",
            "description": f"URL length is {len(normalized)} characters; long URLs with excessive parameters are frequently crafted to obscure target domains in mobile address bars.",
            "source": "LOCAL_HEURISTICS"
        })

    # Flag: Suspicious special characters
    if "@" in parsed.netloc or "@" in normalized:
        indicators.append({
            "type": "LEXICAL",
            "severity": "CRITICAL",
            "title": "Credential/Userinfo '@' Symbol in URL",
            "description": "The URL contains an '@' character which browsers interpret as HTTP basic auth userinfo, effectively redirecting the user to the host following the '@'.",
            "source": "LOCAL_HEURISTICS"
        })

    if "//" in path:
        indicators.append({
            "type": "LEXICAL",
            "severity": "MEDIUM",
            "title": "Multiple Consecutive Slashes in Path",
            "description": "Path contains consecutive slashes ('//') often used in open redirect tricks or parser evasion.",
            "source": "LOCAL_HEURISTICS"
        })

    if subdomain_count >= 3:
        indicators.append({
            "type": "LEXICAL",
            "severity": "MEDIUM",
            "title": f"Deep Subdomain Nesting ({subdomain_count} subdomains)",
            "description": f"Domain features {subdomain_count} nested subdomain labels ('{subdomain}'), typical in dynamic DNS and bulletproof phishing infrastructure.",
            "source": "LOCAL_HEURISTICS"
        })

    if hyphen_count >= 3:
        indicators.append({
            "type": "LEXICAL",
            "severity": "MEDIUM",
            "title": f"Excessive Hyphenation in Host ({hyphen_count} hyphens)",
            "description": f"Host '{host}' contains multiple hyphens, a strong indicator of brand impersonation or typosquatting.",
            "source": "LOCAL_HEURISTICS"
        })

    # Flag: Punycode / IDN Homograph
    has_homoglyphs = "xn--" in host
    if has_homoglyphs:
        indicators.append({
            "type": "IDENTITY",
            "severity": "HIGH",
            "title": "Internationalized Domain / Punycode (IDN Homograph)",
            "description": f"Host contains Punycode prefix 'xn--', which may be used in homoglyph visual spoofing attacks to impersonate legitimate characters.",
            "source": "LOCAL_HEURISTICS"
        })

    # 2. Identity DNA: Brand Impersonation Analysis
    targeted_brand = None
    is_brand_impersonation = False
    full_host_path = f"{host}{path}{query}"

    for brand, legit_domains in TARGETED_BRANDS.items():
        # Check if brand token appears in host, path, or subdomain
        brand_match = re.search(r"(^|[-._/])" + re.escape(brand) + r"([-_./]|$)", full_host_path)
        if brand_match:
            is_legit = any(registered_domain == ld or host == ld or host.endswith("." + ld) for ld in legit_domains)
            if not is_legit:
                targeted_brand = brand
                is_brand_impersonation = True
                indicators.append({
                    "type": "IDENTITY",
                    "severity": "CRITICAL",
                    "title": f"Brand Impersonation Target: {brand.capitalize()}",
                    "description": (
                        f"URL references brand '{brand.capitalize()}', but registered domain '{registered_domain}' "
                        f"does not match genuine authoritative domains ({', '.join(legit_domains)})."
                    ),
                    "source": "LOCAL_HEURISTICS"
                })
                break

    identity_dna = IdentityDNA(
        targeted_brand=targeted_brand,
        has_homoglyphs=has_homoglyphs,
        registered_domain=registered_domain or host,
        is_brand_impersonation=is_brand_impersonation
    )

    # 3. Keyword Analysis
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_host_path]
    evidence["matched_keywords"] = matched_keywords
    if matched_keywords:
        severity = "HIGH" if len(matched_keywords) >= 2 or is_brand_impersonation else "MEDIUM"
        indicators.append({
            "type": "BEHAVIOR",
            "severity": severity,
            "title": f"Credential Harvesting Keywords: {', '.join(matched_keywords[:4])}",
            "description": f"URL path/subdomain contains sensitive authentication keywords: {', '.join(matched_keywords)}.",
            "source": "LOCAL_HEURISTICS"
        })

    return {
        "lexical_dna": lexical_dna,
        "identity_dna": identity_dna,
        "indicators": indicators,
        "limitations": limitations,
        "evidence": evidence,
        "host": host,
        "registered_domain": registered_domain or host
    }

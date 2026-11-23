import re
from typing import Dict, Any, List, Optional
from app.schemas.analysis import BehaviorDNA
from app.services.url_analyzer import analyze_url_heuristics

# Behavioral and Social Engineering Patterns
URGENCY_PATTERNS = [
    r"\bwithin\s+\d+\s*(hours?|hrs?|minutes?|days?)\b",
    r"\bimmediat(ely|e)\s+action\b",
    r"\baction\s+required\b",
    r"\burgent(ly)?\b",
    r"\baccount\s+(will\s+be\s+)?(suspended|terminated|closed|locked)\b",
    r"\bexpires?\s+(today|soon|within)\b",
    r"\bfinal\s+notice\b",
    r"\bact\s+now\b",
    r"\blast\s+warning\b"
]

AUTHORITY_PATTERNS = [
    r"\b(it\s+support|it\s+helpdesk|system\s+administrator|sysadmin)\b",
    r"\b(microsoft|office\s*365|google\s+workspace|apple\s+support)\b",
    r"\b(security\s+team|fraud\s+department|compliance\s+officer)\b",
    r"\b(human\s+resources|hr\s+department|payroll)\b",
    r"\b(internal\s+revenue\s+service|irs|tax\s+authority|hmrc)\b",
    r"\b(federal\s+bureau|police|law\s+enforcement)\b"
]

FEAR_PATTERNS = [
    r"\blegal\s+(action|proceedings|charges)\b",
    r"\baccount\s+(compromised|breached|unauthorized\s+access)\b",
    r"\bpermanent(ly)?\s+(delet(ed|ion)|disabled)\b",
    r"\barrest\s+warrant\b",
    r"\bfinancial\s+penalty\b"
]

FINANCIAL_LURE_PATTERNS = [
    r"\b(lottery|prize|winner|won\s+\$|claim\s+your\s+reward)\b",
    r"\b(tax\s+refund|unclaimed\s+funds?|inheritance|grant)\b",
    r"\b(crypto(currency)?\s+giveaway|bitcoin\s+deposit|eth\s+airdrop)\b"
]

CREDENTIAL_INTENT_PATTERNS = [
    r"\b(verify|confirm|update)\s+your\s+(password|credentials?|pin|security\s+details)\b",
    r"\b(enter|provide)\s+(your\s+)?(login|username\s+and\s+password|2fa|otp|passcode)\b",
    r"\b(social\s+security\s+number|ssn|credit\s+card|cvv)\b",
    r"\breset\s+your\s+password\s+(immediately|now)\b"
]

CTA_PATTERNS = [
    r"\b(click\s+here|click\s+the\s+link|follow\s+this\s+link)\b",
    r"\b(open\s+the\s+attached|download\s+attachment|view\s+invoice)\b",
    r"\b(scan\s+qr\s+code|call\s+toll-free)\b"
]

# URL extraction regex
URL_REGEX = re.compile(
    r"(?:https?://|hxxps?://|[a-zA-Z0-9.-]+\[\.\][a-zA-Z]{2,})[^\s<>\"']+",
    re.IGNORECASE
)


def extract_urls(text: str) -> List[str]:
    """Extracts standard and defanged URLs from message body."""
    raw_matches = URL_REGEX.findall(text)
    cleaned = []
    for m in raw_matches:
        # Refang hxxp -> http and [.] -> .
        refanged = m.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", ".")
        # Strip trailing punctuation
        refanged = re.sub(r"[.,;!?)]+$", "", refanged)
        cleaned.append(refanged)
    return list(dict.fromkeys(cleaned))  # Deduplicate while preserving order


def analyze_message_heuristics(
    message: str,
    sender: Optional[str] = None,
    subject: Optional[str] = None
) -> Dict[str, Any]:
    """
    Analyzes message content, subject, and sender for social engineering tactics,
    credential harvesting intent, and embedded malicious links (FR-02, Section 8).
    """
    full_text = f"{subject or ''}\n{message}".strip().lower()

    indicators: List[Dict[str, Any]] = []
    limitations: List[str] = []
    evidence: Dict[str, Any] = {}

    # Check Behavioral Dimensions
    urgency_hits = [p for p in URGENCY_PATTERNS if re.search(p, full_text)]
    authority_hits = [p for p in AUTHORITY_PATTERNS if re.search(p, full_text)]
    fear_hits = [p for p in FEAR_PATTERNS if re.search(p, full_text)]
    financial_hits = [p for p in FINANCIAL_LURE_PATTERNS if re.search(p, full_text)]
    credential_hits = [p for p in CREDENTIAL_INTENT_PATTERNS if re.search(p, full_text)]
    cta_hits = [p for p in CTA_PATTERNS if re.search(p, full_text)]

    urgency_detected = len(urgency_hits) > 0
    authority_pressure = len(authority_hits) > 0
    fear_detected = len(fear_hits) > 0
    financial_threat = len(financial_hits) > 0 or fear_detected
    credential_intent = len(credential_hits) > 0
    call_to_action = len(cta_hits) > 0

    behavior_dna = BehaviorDNA(
        urgency_detected=urgency_detected,
        authority_pressure=authority_pressure,
        credential_intent=credential_intent,
        financial_threat=financial_threat,
        call_to_action=call_to_action
    )

    evidence["urgency_tactics"] = bool(urgency_detected)
    evidence["authority_impersonation"] = bool(authority_pressure)
    evidence["credential_harvesting_intent"] = bool(credential_intent)
    evidence["call_to_action_present"] = bool(call_to_action)

    # 1. Flag: Credential Harvesting Intent
    if credential_intent:
        indicators.append({
            "type": "BEHAVIOR",
            "severity": "CRITICAL",
            "title": "Direct Credential / Sensitive Data Solicitation",
            "description": "Message urges recipient to disclose passwords, 2FA codes, login credentials, or personal identity numbers.",
            "source": "MESSAGE_ANALYZER"
        })

    # 2. Flag: Artificial Urgency & Coercion
    if urgency_detected:
        indicators.append({
            "type": "BEHAVIOR",
            "severity": "HIGH",
            "title": "Artificial Urgency & Psychological Coercion",
            "description": "Message imposes aggressive time constraints ('within 24 hours', 'immediate action required') to bypass analytical scrutiny.",
            "source": "MESSAGE_ANALYZER"
        })

    # 3. Flag: Authority Impersonation
    if authority_pressure:
        indicators.append({
            "type": "IDENTITY",
            "severity": "HIGH",
            "title": "Organizational / Executive Authority Impersonation",
            "description": "Message claims to originate from IT Support, Microsoft, Security Administration, or Executive management.",
            "source": "MESSAGE_ANALYZER"
        })

    # 4. Flag: Fear / Penalty Threats
    if fear_detected:
        indicators.append({
            "type": "BEHAVIOR",
            "severity": "HIGH",
            "title": "Fear Appeal & Threat of Penalty",
            "description": "Message threatens account termination, legal ramifications, or security penalties to compel compliance.",
            "source": "MESSAGE_ANALYZER"
        })

    # 5. Flag: Financial / Prize Lures
    if financial_hits:
        indicators.append({
            "type": "BEHAVIOR",
            "severity": "MEDIUM",
            "title": "Unsolicited Financial / Reward Lure",
            "description": "Message uses unexpected refunds, prizes, or investment yields as a lure.",
            "source": "MESSAGE_ANALYZER"
        })

    # Extract and analyze embedded URLs
    extracted_urls = extract_urls(message)
    evidence["extracted_urls_count"] = len(extracted_urls)
    embedded_url_analyses = []

    for embedded_url in extracted_urls[:3]:  # Analyze up to first 3 URLs
        url_analysis = analyze_url_heuristics(embedded_url)
        embedded_url_analyses.append(url_analysis)
        # Propagate indicators from embedded URLs into message indicators
        for ind in url_analysis.get("indicators", []):
            indicators.append({
                "type": ind["type"],
                "severity": ind["severity"],
                "title": f"Embedded Link: {ind['title']}",
                "description": f"URL '{embedded_url}': {ind['description']}",
                "source": "MESSAGE_ANALYZER"
            })
        for lim in url_analysis.get("limitations", []):
            limitations.append(lim)

    if not extracted_urls:
        limitations.append(
            "No embedded hyperlinks detected in message text. Message may rely on phone callback (vishing) or reply-based fraud."
        )

    # Sender header check
    if sender:
        sender_clean = sender.strip().lower()
        evidence["sender"] = sender_clean
        if any(free in sender_clean for free in ["@gmail.com", "@yahoo.com", "@hotmail.com"]) and authority_pressure:
            indicators.append({
                "type": "IDENTITY",
                "severity": "HIGH",
                "title": "Free Webmail Sender Impersonating Corporate Authority",
                "description": f"Sender address '{sender_clean}' is a free public webmail service while claiming corporate/IT authority.",
                "source": "MESSAGE_ANALYZER"
            })

    return {
        "behavior_dna": behavior_dna,
        "indicators": indicators,
        "limitations": limitations,
        "evidence": evidence,
        "extracted_urls": extracted_urls,
        "embedded_url_analyses": embedded_url_analyses
    }

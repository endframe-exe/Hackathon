from typing import List, Dict, Any, Tuple

SEVERITY_WEIGHTS = {
    "CRITICAL": 35.0,
    "HIGH": 20.0,
    "MEDIUM": 10.0,
    "LOW": 5.0,
    "INFO": 0.0
}

SAFETY_DISCLAIMER = (
    "Disclaimer: PhishGuard AI provides automated heuristics, behavioral analysis, and external threat intelligence. "
    "No automated detection engine guarantees 100% identification of novel or spear-phishing campaigns. "
    "Always exercise caution and independently verify unexpected requests through trusted out-of-band communication channels."
)


def calculate_risk(
    indicators: List[Dict[str, Any]],
    input_type: str = "url"
) -> Tuple[float, str, str, List[str]]:
    """
    Computes a normalized risk score (0.0 - 100.0), risk level, verdict,
    and tailored recommendations based on detected threat indicators.
    """
    raw_score = 0.0
    critical_count = 0
    high_count = 0
    medium_count = 0

    for ind in indicators:
        sev = ind.get("severity", "INFO").upper()
        weight = SEVERITY_WEIGHTS.get(sev, 0.0)
        raw_score += weight
        if sev == "CRITICAL":
            critical_count += 1
        elif sev == "HIGH":
            high_count += 1
        elif sev == "MEDIUM":
            medium_count += 1

    # Calibrate score and assign level
    if critical_count >= 2 or (critical_count >= 1 and high_count >= 1):
        score = min(100.0, max(85.0, raw_score))
        level = "CRITICAL"
    elif critical_count >= 1:
        score = min(95.0, max(75.0, raw_score))
        level = "CRITICAL" if score >= 80.0 else "HIGH"
    elif high_count >= 2:
        score = min(85.0, max(65.0, raw_score))
        level = "HIGH"
    elif high_count == 1:
        score = min(60.0, max(35.0, raw_score))
        level = "HIGH" if score >= 55.0 else "MEDIUM"
    elif medium_count >= 2:
        score = min(50.0, max(30.0, raw_score))
        level = "MEDIUM"
    elif medium_count == 1:
        score = 25.0
        level = "MEDIUM"
    elif raw_score > 0:
        score = min(20.0, raw_score)
        level = "LOW"
    else:
        score = 5.0
        level = "LOW"

    score = round(score, 1)

    # Contextual Verdict
    if level == "CRITICAL":
        verdict = (
            f"Dangerous {input_type.upper()} with multiple confirmed phishing markers, "
            "brand impersonation, or active threat intelligence detections. Do not engage."
        )
    elif level == "HIGH":
        verdict = (
            f"High-probability phishing {input_type}. Exhibits structural anomalies, "
            "deceptive cues, or high-risk domain configuration."
        )
    elif level == "MEDIUM":
        verdict = (
            f"Suspicious {input_type} requiring elevated caution. Contains cloaked redirects, "
            "social engineering pressure, or sensitive keyword patterns."
        )
    else:
        verdict = (
            f"Low-risk {input_type}. Standard structural characteristics observed with "
            "no overt phishing signatures detected in local or external heuristics."
        )

    # Actionable Recommendations
    recommendations: List[str] = []

    if critical_count > 0 or high_count > 0:
        recommendations.append("Do NOT submit passwords, MFA tokens, or sensitive personal data.")
        recommendations.append("Do not click links or download any files attached to this communication.")

    if any(ind.get("type") == "IDENTITY" for ind in indicators):
        recommendations.append(
            "Navigate directly to the official vendor website via a bookmarked URL or search engine instead of clicking provided links."
        )

    if any(ind.get("type") == "BEHAVIOR" for ind in indicators):
        recommendations.append(
            "Ignore urgent deadlines designed to induce panic; verify claims directly with the organization via official phone/support."
        )

    if input_type == "message":
        recommendations.append("Report this message as phishing/spam to your IT Security or SOC helpdesk.")
        recommendations.append("Block and delete the sender address from your email client.")
    else:
        recommendations.append("Report this URL to Google Safe Browsing and Microsoft SmartScreen if confirmed malicious.")

    if level == "LOW":
        recommendations.append("Target appears low risk, but maintain standard vigilance when entering credentials.")

    return score, level, verdict, recommendations

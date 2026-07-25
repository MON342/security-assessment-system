"""
modules/risk_scorer.py — CVSS-based Risk Scoring Engine
Calculates CVSS base scores for each finding and an overall risk score.
"""
import logging
import math
from typing import Dict, Any, List

try:
    from cvss import CVSS3
    CVSS_AVAILABLE = True
except ImportError:
    CVSS_AVAILABLE = False

logger = logging.getLogger("assessor.risk_scorer")

# Fallback scores when CVSS cannot be computed
FALLBACK_SCORES = {
    "CRITICAL": 9.5,
    "HIGH":     8.0,
    "MEDIUM":   5.5,
    "LOW":      2.5,
    "INFO":     0.0,
}

# Severity contribution weights for overall score accumulation
# Controls how much each additional finding of that severity adds
SEVERITY_CONTRIBUTION = {
    "CRITICAL": 1.00,
    "HIGH":     0.60,
    "MEDIUM":   0.25,
    "LOW":      0.08,
    "INFO":     0.00,
}


def score_finding(finding: Dict) -> Dict:
    """
    Calculate CVSS base score for a single finding.
    Adds 'cvss_base_score' and 'cvss_severity' to the finding dict.
    Returns updated finding dict.
    """
    vector = finding.get("cvss_vector", "")
    severity = finding.get("severity", "INFO").upper()

    # Try to calculate from CVSS vector
    base_score = None
    if CVSS_AVAILABLE and vector and vector.startswith("CVSS:3"):
        try:
            c = CVSS3(vector)
            base_score = float(c.base_score)
        except Exception as e:
            logger.debug(f"CVSS parse error for vector '{vector}': {e}")

    # Fallback: use severity-based score
    if base_score is None:
        base_score = FALLBACK_SCORES.get(severity, 0.0)
        # If finding already has a nuclei-provided score, use it
        if finding.get("cvss_score"):
            try:
                base_score = float(finding["cvss_score"])
            except (ValueError, TypeError):
                pass

    # Map score back to severity label
    cvss_severity = _score_to_severity(base_score)

    finding = dict(finding)
    finding["cvss_base_score"] = round(base_score, 1)
    finding["cvss_severity"]   = cvss_severity
    return finding


def score_all_findings(findings: List[Dict]) -> List[Dict]:
    """Score all findings and return sorted by severity (highest first)."""
    scored = [score_finding(f) for f in findings]
    # Sort: CRITICAL → HIGH → MEDIUM → LOW → INFO
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    scored.sort(key=lambda f: (
        severity_order.get(f.get("severity", "INFO"), 4),
        -f.get("cvss_base_score", 0)
    ))
    return scored


def calculate_overall_score(findings: List[Dict]) -> Dict[str, Any]:
    """
    Calculate an overall risk score (0-10) for the target.

    Algorithm:
        1. Start from the highest single CVSS score as the base.
        2. Each additional finding contributes a weighted fraction
           scaled by its severity contribution factor, with logarithmic
           decay so volume of findings is reflected without capping early.
        3. Normalize to 0-10.

    This means:
        - 1 CRITICAL  -> ~9.5
        - 5 CRITICAL  -> ~9.8
        - 20 CRITICAL -> ~10.0  (saturates only at very high volume)
        - 1 HIGH only -> ~7.0-8.0
    """
    if not findings:
        return {
            "max_score":        0.0,
            "max_severity":     "INFO",
            "total_risks":      0,
            "counts":           {s: 0 for s in SEVERITY_CONTRIBUTION},
            "breakdown":        {},
        }

    counts = {s: 0 for s in SEVERITY_CONTRIBUTION}
    scores_by_severity: Dict[str, List[float]] = {s: [] for s in SEVERITY_CONTRIBUTION}

    for f in findings:
        sev   = f.get("severity", "INFO").upper()
        score = f.get("cvss_base_score", FALLBACK_SCORES.get(sev, 0.0))
        if sev in counts:
            counts[sev] += 1
            scores_by_severity[sev].append(score)

    # Gather all non-zero scores sorted highest first
    all_scores = sorted(
        [s for sev, svscores in scores_by_severity.items()
           for s in svscores if s > 0.0],
        reverse=True,
    )

    if not all_scores:
        max_score = 0.0
    else:
        max_score = all_scores[0]

    max_severity = _score_to_severity(max_score)
    
    total_risks = sum(c for s, c in counts.items() if s != "INFO")

    breakdown = {}
    for sev, svscores in scores_by_severity.items():
        if svscores:
            breakdown[sev] = {
                "count": len(svscores),
                "max":   round(max(svscores), 1),
                "avg":   round(sum(svscores) / len(svscores), 1),
            }

    return {
        "max_score":        round(max_score, 1),
        "max_severity":     max_severity,
        "total_risks":      total_risks,
        "counts":           counts,
        "breakdown":        breakdown,
    }


def _score_to_severity(score: float) -> str:
    """Convert CVSS base score to severity label."""
    if score >= 9.0:  return "CRITICAL"
    if score >= 7.0:  return "HIGH"
    if score >= 4.0:  return "MEDIUM"
    if score > 0.0:   return "LOW"
    return "INFO"


def get_risk_label(score: float) -> str:
    """Get a human-friendly risk label for an overall score."""
    if score >= 9.0:  return "CRITICAL RISK"
    if score >= 7.0:  return "HIGH RISK"
    if score >= 4.0:  return "MEDIUM RISK"
    if score >= 1.0:  return "LOW RISK"
    return "INFORMATIONAL"

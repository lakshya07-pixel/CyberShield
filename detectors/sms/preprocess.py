"""
SMS Text Preprocessing and Normalization Module.
Normalizes high-variance entities (URLs, Indian currency figures, OTP/phone digit strings)
and extracts contextual scam keywords for the CyberShield Challenge.
"""

import re
from typing import List

SCAM_KEYWORDS: List[str] = [
    "urgent", "verify", "block", "kyc", "claim", "prize", "winner", "lottery",
    "free", "refund", "loan", "suspend", "deactivat", "congratulations",
    "click", "password", "redeem", "coupon", "expire", "deposit", "reward", "cashback",
]


def clean_sms_text(text: str) -> str:
    """
    Cleans raw SMS text into normalized entity tokens.

    Args:
        text: Raw SMS message string.

    Returns:
        Cleaned lowercase string with entity replacements.

    Raises:
        ValueError: If input is empty or whitespace-only.
    """
    t = text.strip()
    if not t:
        raise ValueError("SMS text cannot be empty or whitespace-only.")

    t_lower = t.lower()
    # Normalize web links
    t_lower = re.sub(r"http\S+|www\.\S+|bit\.ly\S+|tinyurl\S+", " <URL> ", t_lower)
    # Normalize currency figures ($, Rs., ₹, INR)
    t_lower = re.sub(r"(\$|rs\.?|₹|inr)\s?\d+[,.]?\d*", " <MONEY> ", t_lower)
    # Normalize long digit sequences (OTPs, account numbers, phone numbers)
    t_lower = re.sub(r"\d{4,}", " <NUM> ", t_lower)
    # Strip remaining punctuation/special characters while preserving token tags
    t_lower = re.sub(r"[^a-zA-Z<>\s]", " ", t_lower)
    # Collapse consecutive whitespace
    t_lower = re.sub(r"\s+", " ", t_lower).strip()

    return t_lower


def extract_sms_keywords(text: str) -> List[str]:
    """Returns all matched scam keywords in the input text."""
    t_lower = text.lower()
    return [k for k in SCAM_KEYWORDS if k in t_lower]


def extract_sms_indicators(text: str, is_threat: bool) -> List[str]:
    """
    Extracts contextual security indicators for SMS messages.
    """
    indicators: List[str] = []
    if not is_threat:
        return indicators

    t_lower = text.lower()
    hits = extract_sms_keywords(text)
    if hits:
        indicators.append(f"Scam keywords detected: {', '.join(hits[:5])}")

    if any(k in t_lower for k in ["http", "www.", "bit.ly", "tinyurl"]) or (
        "click" in t_lower and ("link" in t_lower or "here" in t_lower)
    ):
        indicators.append("Contains suspicious link or urgent call-to-click")

    if any(k in t_lower for k in ["password", "username", "pin", "cvv", "otp"]):
        indicators.append("Solicits confidential user credentials or authentication codes")

    if any(ch.isdigit() for ch in text) and any(
        k in t_lower for k in ["rs", "₹", "rupee", "lakh", "crore", "prize", "won"]
    ):
        indicators.append("References financial prize, lottery amount, or monetary demand")

    return indicators


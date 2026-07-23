import copy
import hashlib
import base64
import random
import string
from typing import Any, Dict, List, Optional, Union

TRANSFORMATION_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
DEFAULT_SENSITIVE_FIELDS = {
    "password",
    "passwd",
    "pass",
    "ssn",
    "social_security",
    "account",
    "account_number",
    "credit_card",
    "card_number",
    "salary",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "pin",
    "cvv",
    "email",
}

DECAY_PREFIXES = ["USER_", "PROTECTED_", "DECOY_", "HIDDEN_"]


def is_sensitive_key(key: str, extra_sensitive: Optional[List[str]] = None) -> bool:
    if not key:
        return False
    normalized = key.strip().lower()
    if normalized in DEFAULT_SENSITIVE_FIELDS:
        return True
    if extra_sensitive and normalized in {field.lower() for field in extra_sensitive}:
        return True
    return any(token in normalized for token in ["password", "ssn", "secret", "token", "account", "credit", "salary", "pin", "apikey", "private"])


def deep_copy_payload(payload: Any) -> Any:
    return copy.deepcopy(payload)


def mask_value(value: Any) -> str:
    if value is None:
        return "***"
    raw = str(value)
    if len(raw) <= 4:
        return "*" * len(raw)
    if raw.isdigit():
        visible = raw[-4:]
        return "X" * (len(raw) - 4) + visible
    prefix = raw[:2]
    suffix = raw[-2:]
    masked = prefix + "*" * max(2, len(raw) - 4) + suffix
    return masked


def hash_value(value: Any) -> str:
    raw = str(value).encode("utf-8")
    sha = hashlib.sha256(raw).hexdigest()
    return sha


def encrypt_value(value: Any) -> str:
    raw = str(value).encode("utf-8")
    digest = hashlib.sha256(raw).digest()
    encoded = base64.urlsafe_b64encode(digest).decode("utf-8")
    return encoded


def make_decoy_value(field_name: Optional[str] = None) -> str:
    prefix = random.choice(DECAY_PREFIXES)
    suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    if field_name:
        normalized = field_name.strip().upper()
        if normalized.startswith("NAME"):
            return f"{prefix}USER_{suffix}"
        if normalized.startswith("ACCOUNT") or normalized.startswith("CARD"):
            return f"{prefix}{suffix}"
        if normalized.startswith("SALARY") or normalized.startswith("PAYMENT"):
            return "0"
        if normalized.startswith("PASSWORD") or normalized.startswith("SECRET"):
            return "PROTECTED"
    return f"{prefix}{suffix}"


def transform_value(value: Any, key: Optional[str], level: str) -> Any:
    if level == "LOW":
        return value

    if level == "MEDIUM":
        return mask_value(value)

    if level == "HIGH":
        if key and is_sensitive_key(key):
            if key.strip().lower() in {"password", "pass", "passwd", "secret", "private_key"}:
                return hash_value(value)
            return encrypt_value(value)
        return mask_value(value)

    if level == "CRITICAL":
        if key and is_sensitive_key(key):
            return make_decoy_value(key)
        if isinstance(value, str):
            return "PROTECTED"
        if isinstance(value, (int, float)):
            return 0
        if isinstance(value, bool):
            return False
        return None

    return value


def transform_payload(
    payload: Any,
    level: str = "LOW",
    extra_sensitive_fields: Optional[List[str]] = None,
    preserve_keys: Optional[List[str]] = None,
) -> Any:
    if level not in TRANSFORMATION_LEVELS:
        level = "LOW"
    preserve_keys = [k.lower() for k in (preserve_keys or [])]

    if payload is None:
        return payload

    if isinstance(payload, dict):
        transformed = {}
        for key, value in payload.items():
            if key and key.lower() in preserve_keys:
                transformed[key] = deep_copy_payload(value)
                continue
            if isinstance(value, (dict, list)):
                transformed[key] = transform_payload(value, level, extra_sensitive_fields, preserve_keys)
                continue
            if is_sensitive_key(key, extra_sensitive_fields):
                transformed[key] = transform_value(value, key, level)
            else:
                if level == "CRITICAL":
                    if isinstance(value, (dict, list)):
                        transformed[key] = transform_payload(value, level, extra_sensitive_fields, preserve_keys)
                    else:
                        transformed[key] = make_decoy_value(key)
                else:
                    transformed[key] = value
        return transformed

    if isinstance(payload, list):
        return [transform_payload(item, level, extra_sensitive_fields, preserve_keys) for item in payload]

    if isinstance(payload, str):
        return transform_value(payload, None, level)

    return payload


def build_protected_response(
    original: Any,
    level: str,
    extra_sensitive_fields: Optional[List[str]] = None,
    preserve_keys: Optional[List[str]] = None,
    status_label: Optional[str] = None,
) -> Dict[str, Any]:
    response = {
        "status": status_label or "PROTECTED",
        "transformation_level": level,
        "data": transform_payload(original, level, extra_sensitive_fields, preserve_keys),
    }
    return response


def determine_transformation_level(
    threat_score: float,
    high_confidence: float = 90.0,
    thresholds: Optional[Dict[str, float]] = None,
) -> str:
    if thresholds is None:
        thresholds = {"MEDIUM": 25.0, "HIGH": 55.0, "CRITICAL": 85.0}

    if threat_score >= thresholds["CRITICAL"]:
        return "CRITICAL"
    if threat_score >= thresholds["HIGH"]:
        return "HIGH"
    if threat_score >= thresholds["MEDIUM"]:
        return "MEDIUM"
    return "LOW"


def summarize_transformation(level: str) -> str:
    summaries = {
        "LOW": "Original response returned",
        "MEDIUM": "Sensitive fields masked",
        "HIGH": "Sensitive fields encrypted or hashed",
        "CRITICAL": "Decoy/protected response sent",
    }
    return summaries.get(level, "Original response returned")

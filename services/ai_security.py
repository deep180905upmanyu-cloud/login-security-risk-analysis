from datetime import datetime
from typing import Any, Dict, List


def _parse_login_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        text = str(value).strip()
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _count_recent_attempts(recent_attempts: List[Dict[str, Any]]) -> int:
    count = 0
    for attempt in recent_attempts or []:
        attempt_time = _parse_login_time(attempt.get("attempt_time") or attempt.get("login_time"))
        if attempt_time is None:
            continue
        if (datetime.now() - attempt_time).total_seconds() <= 3600:
            count += 1
    return count


def build_fallback_analysis(activity: Dict[str, Any]) -> Dict[str, str]:
    failed_attempts = int(activity.get("failed_attempts", 0) or 0)
    account_status = str(activity.get("account_status", "ACTIVE")).upper()
    recent_attempts = activity.get("recent_login_attempts") or []
    recent_window_count = _count_recent_attempts(recent_attempts)
    login_time = _parse_login_time(activity.get("login_time"))

    risk_level = "LOW"
    reason = "The login activity appears normal."
    recommendation = "Continue standard monitoring."

    if account_status == "LOCKED" or failed_attempts >= 5:
        risk_level = "HIGH"
        reason = "The account is locked or there have been repeated failed login attempts."
        recommendation = "Require verification and review recent login attempts before allowing access."
    elif failed_attempts >= 3:
        risk_level = "MEDIUM"
        reason = "Multiple failed login attempts suggest suspicious activity."
        recommendation = "Review recent login attempts and confirm the user before continuing."

    suspicious_recent = sum(
        1
        for attempt in recent_attempts
        if str(attempt.get("status", "")).upper() in {"SUSPICIOUS", "LOCKED"}
        or str(attempt.get("risk_level", "")).upper() in {"MEDIUM", "HIGH"}
    )
    if suspicious_recent >= 2 and risk_level == "LOW":
        risk_level = "MEDIUM"
        reason = "Recent suspicious login history indicates elevated risk."
        recommendation = "Review recent login activity and enforce extra verification."

    if recent_window_count >= 5 and risk_level == "LOW":
        risk_level = "MEDIUM"
        reason = "Frequent recent login attempts suggest abnormal account activity."
        recommendation = "Monitor the account closely and review the login pattern."

    if login_time is not None and (login_time.hour < 3 or login_time.hour >= 22):
        if risk_level == "LOW":
            risk_level = "MEDIUM"
            reason = "The login occurred at an unusual time for this account."
            recommendation = "Review the login time and confirm whether the activity is expected."

    return {
        "risk_level": risk_level,
        "reason": reason,
        "recommendation": recommendation,
    }


def analyze_login_activity(activity: Dict[str, Any]) -> Dict[str, str]:
    return build_fallback_analysis(activity)

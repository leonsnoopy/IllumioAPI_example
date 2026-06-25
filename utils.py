import sys
import re
from datetime import datetime, timezone, timedelta

def reconfigure_stdout():
    """
    Reconfigures stdout to use UTF-8 to prevent encoding issues on Windows consoles.
    """
    if sys.platform.startswith("win"):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except AttributeError:
            import io
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

def convert_utc_to_taiwan_time(utc_str):
    """
    Parses a UTC ISO8601 string (e.g. '2026-06-25T02:44:39.392Z')
    and converts it to Taiwan Time (UTC+8) formatted string 'YYYY-MM-DD HH:MM:SS'.
    """
    if not utc_str or utc_str == "N/A":
        return "N/A"
    try:
        # Normalize trailing Z to offset format for older python compatibility
        clean_str = utc_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_str)
        
        # Fallback to UTC if timezone-naive
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
            
        # Convert to Taiwan Time (UTC+8)
        tw_tz = timezone(timedelta(hours=8))
        tw_dt = dt.astimezone(tw_tz)
        return tw_dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return utc_str

def get_event_description(event):
    """
    Constructs a human-readable description for an event from the PCE JSON,
    matching what is shown on the Illumio PCE web portal.
    """
    if not event:
        return "N/A"
        
    # 1. Check for action errors (for failed events)
    action_data = event.get("action")
    if isinstance(action_data, dict):
        errors = action_data.get("errors")
        if isinstance(errors, list) and len(errors) > 0:
            msg = errors[0].get("message")
            if msg:
                return msg

    # 2. Check notifications
    notifications = event.get("notifications")
    if isinstance(notifications, list) and len(notifications) > 0:
        first_notif = notifications[0]
        if isinstance(first_notif, dict):
            info = first_notif.get("info", {})
            notif_type = first_notif.get("notification_type", "")
            
            # User session notifications
            if "user.pce_session" in notif_type or "user" in info:
                user_info = info.get("user", {})
                username = user_info.get("username") or user_info.get("email") or "User"
                if "created" in notif_type:
                    return f"Session created for {username}"
                elif "terminated" in notif_type:
                    reason = info.get("reason", "unknown")
                    return f"Session terminated ({reason}) for {username}"
                
            # If there's general warning/error messages or details in info
            if isinstance(info, dict):
                reason = info.get("reason")
                if reason:
                    return str(reason)
                msg = info.get("message")
                if msg:
                    return str(msg)

    # 3. Check resource changes
    resource_changes = event.get("resource_changes")
    if isinstance(resource_changes, list) and len(resource_changes) > 0:
        first_change = resource_changes[0]
        if isinstance(first_change, dict):
            resource = first_change.get("resource", {})
            # If it's a workload change
            workload = resource.get("workload", {})
            if isinstance(workload, dict):
                wl_name = workload.get("name") or workload.get("hostname")
                if wl_name:
                    change_type = first_change.get("change_type", "update")
                    return f"{change_type.title()}d interfaces on workload {wl_name}"

    # 4. Fallback to formatting the event type as a friendly string
    etype = event.get("event_type")
    if etype:
        # Check specific known types
        if etype == "agent.tampering":
            return "Agent tampering detected"
        elif etype == "agent.request_policy":
            status = event.get("status")
            if status == "success":
                return "Agent policy requested successfully"
            else:
                return "Agent policy request failed"
                
        # Generic fallback
        return etype.replace("_", " ").replace(".", " ").title()
        
    return "N/A"

def print_separator(title):
    """
    Prints a consistent terminal separator bar with a centered title.
    """
    print("\n" + "=" * 60)
    print(f" {title} ".center(60, "="))
    print("=" * 60)

def parse_selection_indices(input_str, max_val):
    """
    Parses a string of comma-separated or space-separated numbers and ranges (e.g. '1, 2, 4-6').
    Returns a sorted list of unique valid 1-based indices.
    """
    indices = set()
    # Replace space delimiters with commas
    normalized = input_str.replace(" ", ",")
    parts = normalized.split(",")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start_str, end_str = part.split("-", 1)
                start_i = int(start_str.strip())
                end_i = int(end_str.strip())
                for i in range(min(start_i, end_i), max(start_i, end_i) + 1):
                    if 1 <= i <= max_val:
                        indices.add(i)
            except ValueError:
                pass
        else:
            try:
                i = int(part)
                if 1 <= i <= max_val:
                    indices.add(i)
            except ValueError:
                pass
    return sorted(list(indices))

def validate_time(time_str):
    """
    Validates if a string is in HH:MM format (24-hour).
    """
    if not re.match(r"^\d{2}:\d{2}$", time_str):
        return False
    try:
        hh, mm = map(int, time_str.split(":"))
        return 0 <= hh <= 23 and 0 <= mm <= 59
    except ValueError:
        return False

def parse_weekdays(weekdays_str):
    """
    Parses and validates a comma-separated list of weekdays.
    Returns (list of valid weekdays, error_msg).
    """
    valid_set = {"MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"}
    if not weekdays_str:
        return None, "請輸入至少一個星期名稱。"
    
    parts = [p.strip().upper() for p in weekdays_str.replace(" ", ",").split(",")]
    cleaned = []
    for p in parts:
        if not p:
            continue
        if p not in valid_set:
            return None, f"無效的星期名稱: {p}。必須是 MON, TUE, WED, THU, FRI, SAT, SUN 之一。"
        if p not in cleaned:
            cleaned.append(p)
            
    if not cleaned:
        return None, "未解析到 any 有效的星期。"
    return cleaned, None

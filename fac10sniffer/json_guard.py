import json
from uuid import UUID
from datetime import datetime
from systemd import journal


def is_json_safe(obj):
    if isinstance(obj, dict):
        return {k: is_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [is_json_safe(v) for v in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, journal.Monotonic):
        return str(obj)

    if isinstance(obj, (int, str, float, bool)) or obj is None:
        return obj

    return str(obj)

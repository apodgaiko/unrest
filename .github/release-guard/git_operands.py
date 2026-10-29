"""Bounded Git data operands; application value provenance is not certified."""
from datetime import datetime

from content_manifest import Refused


def text(value):
    if type(value) is not str or not value or len(value) > 4096 or '\0' in value:
        raise Refused('git value primitive')
    try:
        if len(value.encode('utf-8')) > 4096:
            raise Refused('git value text bound')
    except UnicodeError:
        raise Refused('git value text encoding') from None
    return value


def digest(value, length=40):
    if type(value) is not str or len(value) != length or any(c not in '0123456789abcdef' for c in value):
        raise Refused('git value digest')
    return value


def date_text(value):
    text(value)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise Refused('git value date') from None
    canonical = parsed.isoformat()
    alternatives = (canonical, canonical[:-6] + 'Z') if canonical.endswith('+00:00') else (canonical,)
    if parsed.tzinfo is None or value not in alternatives:
        raise Refused('git value canonical date')
    return value

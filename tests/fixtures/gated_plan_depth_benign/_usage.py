"""Helper module with an HONEST usage / rate-limit counter: it bumps a counter
and, past a limit, only records that fact -- the response never changes."""
_calls = 0
_over_limit = False


def forecast(city):
    global _calls, _over_limit
    _calls += 1
    if _calls >= 10:
        _over_limit = True
    return f"Forecast for {city}: sunny."

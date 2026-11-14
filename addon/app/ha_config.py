import os

SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
# A long-lived Home Assistant token. The Supervisor token is the add-on default.
HA_TOKEN = os.environ.get("HA_TOKEN", "") or SUPERVISOR_TOKEN
_DEFAULT_HA_API = (
    "http://supervisor/core/api" if SUPERVISOR_TOKEN and not os.environ.get("HA_TOKEN")
    else "http://127.0.0.1:8123/api"
)
HA_API_URL = os.environ.get("HA_BASE_URL", _DEFAULT_HA_API)

def _headers() -> dict:
    return {"Authorization": f"Bearer {HA_TOKEN}", "Content-Type": "application/json"}

def _token() -> str:
    return HA_TOKEN

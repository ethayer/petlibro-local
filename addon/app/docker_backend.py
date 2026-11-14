"""Mosquitto login management for a standalone Docker broker.

Used when MOSQUITTO_PASSWORD_FILE is set. The Supervisor add-on API is not
available on Home Assistant Container. This talks to the Docker socket to
stop, start, and reload the broker, and writes Mosquitto's password and ACL
files directly.
"""

import asyncio
import base64
import hashlib
import hmac
import logging
import os
import subprocess

import aiohttp

_LOGGER = logging.getLogger(__name__)

_APP_TOPICS = (
    "topic readwrite dl/#",
    "topic readwrite petlibro_local/#",
    "topic write homeassistant/#",
)
_DEVICE_TOPICS = ("topic readwrite dl/#",)


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def password_file() -> str:
    return _env("MOSQUITTO_PASSWORD_FILE")


def acl_file() -> str:
    return _env("MOSQUITTO_ACL_FILE")


def _container() -> str:
    return _env("MOSQUITTO_CONTAINER", "mosquitto")


def _socket() -> str:
    return _env("DOCKER_SOCKET", "/var/run/docker.sock")


def _protected() -> set[str]:
    raw = _env("MOSQUITTO_PROTECTED_USERS", "admin")
    return {part.strip() for part in raw.split(",") if part.strip()}


def _app_user() -> str:
    return _env("MQTT_USER")


def _file_owner() -> tuple[int, int]:
    return int(_env("MOSQUITTO_FILE_UID", "1000")), int(_env("MOSQUITTO_FILE_GID", "1000"))


def _fix_owner(path: str) -> None:
    uid, gid = _file_owner()
    os.chown(path, uid, gid)
    os.chmod(path, 0o600)


def _read_users(path: str) -> dict[str, str]:
    users: dict[str, str] = {}
    if not os.path.exists(path):
        return users
    with open(path) as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            username, hashed = line.split(":", 1)
            users[username] = hashed
    return users


def password_matches(stored: str, password: str) -> bool:
    """True when stored is a Mosquitto $7$ (PBKDF2-SHA512) hash of password."""
    parts = stored.split("$")
    if len(parts) != 5 or parts[1] != "7":
        return False
    try:
        iterations = int(parts[2])
        salt = base64.b64decode(parts[3])
        expected = base64.b64decode(parts[4])
    except (ValueError, TypeError):
        return False
    derived = hashlib.pbkdf2_hmac(
        "sha512", password.encode(), salt, iterations, dklen=len(expected)
    )
    return hmac.compare_digest(derived, expected)


def _topics_for(username: str) -> tuple[str, ...]:
    if username and username == _app_user():
        return _APP_TOPICS
    return _DEVICE_TOPICS


def _write_acl(username: str) -> bool:
    """Ensure username has its topic block. Returns True when the file changed."""
    path = acl_file()
    if not path:
        raise RuntimeError("MOSQUITTO_ACL_FILE is not set")
    topics = list(_topics_for(username))
    existing = ""
    if os.path.exists(path):
        with open(path) as handle:
            existing = handle.read()
    kept: list[str] = []
    lines = existing.splitlines()
    index = 0
    while index < len(lines):
        if lines[index].strip() == f"user {username}":
            index += 1
            while index < len(lines) and not lines[index].startswith("user "):
                index += 1
            continue
        kept.append(lines[index])
        index += 1
    while kept and not kept[-1].strip():
        kept.pop()
    block = [f"user {username}", *topics]
    new_lines = [*kept, "", *block] if kept else block
    updated = "\n".join(new_lines).rstrip() + "\n"
    if updated == existing:
        return False
    with open(path, "w") as handle:
        handle.write(updated)
    _fix_owner(path)
    return True


def _remove_acl(username: str) -> bool:
    path = acl_file()
    if not path or not os.path.exists(path):
        return False
    with open(path) as handle:
        lines = handle.read().splitlines()
    kept: list[str] = []
    index = 0
    found = False
    while index < len(lines):
        if lines[index].strip() == f"user {username}":
            found = True
            index += 1
            while index < len(lines) and not lines[index].startswith("user "):
                index += 1
            continue
        kept.append(lines[index])
        index += 1
    if not found:
        return False
    updated = "\n".join(kept).rstrip() + "\n"
    with open(path, "w") as handle:
        handle.write(updated)
    _fix_owner(path)
    return True


def _passwd(username: str, password: str | None, delete: bool = False) -> None:
    path = password_file()
    if not path:
        raise RuntimeError("MOSQUITTO_PASSWORD_FILE is not set")
    if delete:
        cmd = ["mosquitto_passwd", "-D", path, username]
    else:
        cmd = ["mosquitto_passwd", "-b", path, username, password or ""]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "mosquitto_passwd failed").strip()
        raise RuntimeError(detail)
    _fix_owner(path)


def add_login(username: str, password: str, allow_update: bool = False) -> str:
    if username in _protected():
        _LOGGER.warning("Refusing to change protected Mosquitto login %s", username)
        return "conflict"
    users = _read_users(password_file())
    stored = users.get(username)
    changed = False
    if stored is None:
        _passwd(username, password)
        changed = True
    elif password_matches(stored, password):
        pass
    elif not allow_update:
        _LOGGER.warning("Mosquitto login %s... exists and was not updated", username[:4])
        return "conflict"
    else:
        _passwd(username, password)
        changed = True
    if _write_acl(username):
        changed = True
    return "added" if changed else "exists"


def remove_login(username: str) -> str:
    if username in _protected():
        _LOGGER.warning("Refusing to remove protected Mosquitto login %s", username)
        return "error"
    users = _read_users(password_file())
    if username not in users:
        _remove_acl(username)
        return "not_found"
    _passwd(username, None, delete=True)
    _remove_acl(username)
    return "removed"


async def _docker(method: str, path: str) -> tuple[int, str]:
    socket_path = _socket()
    if not os.path.exists(socket_path):
        raise RuntimeError(f"Docker socket {socket_path} is not available")
    connector = aiohttp.UnixConnector(path=socket_path)
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        async with session.request(method, f"http://localhost/v1.41{path}") as resp:
            return resp.status, await resp.text()


def _ok(status: int) -> bool:
    return status in (200, 204, 304)


async def stop_mosquitto() -> bool:
    name = _container()
    try:
        status, text = await _docker("POST", f"/containers/{name}/stop?t=10")
    except Exception:
        _LOGGER.exception("Could not stop Mosquitto container %s", name)
        return False
    if _ok(status):
        _LOGGER.info("Stopped Mosquitto container %s", name)
        return True
    _LOGGER.error("Stop Mosquitto failed: HTTP %s — %s", status, text[:200])
    return False


async def start_mosquitto() -> bool:
    name = _container()
    try:
        status, text = await _docker("POST", f"/containers/{name}/start")
    except Exception:
        _LOGGER.exception("Could not start Mosquitto container %s", name)
        return False
    if _ok(status):
        _LOGGER.info("Started Mosquitto container %s", name)
        return True
    _LOGGER.error("Start Mosquitto failed: HTTP %s — %s", status, text[:200])
    return False


async def reload_mosquitto() -> bool:
    """Ask Mosquitto to reread its password and ACL files without a restart."""
    name = _container()
    try:
        status, text = await _docker("POST", f"/containers/{name}/kill?signal=HUP")
    except Exception:
        _LOGGER.exception("Could not reload Mosquitto container %s", name)
        return False
    if _ok(status):
        _LOGGER.info("Reloaded Mosquitto container %s", name)
        return True
    _LOGGER.error("Reload Mosquitto failed: HTTP %s — %s", status, text[:200])
    return False


async def container_info() -> dict:
    name = _container()
    try:
        status, text = await _docker("GET", f"/containers/{name}/json")
    except Exception:
        _LOGGER.exception("Could not read Mosquitto container %s", name)
        return {}
    if status != 200:
        _LOGGER.error("Mosquitto info failed: HTTP %s — %s", status, text[:200])
        return {}
    import json
    body = json.loads(text)
    running = body.get("State", {}).get("Running", False)
    return {"state": "started" if running else "stopped", "version": "docker"}


async def ensure_app_login() -> None:
    """Create the app's own broker login from MQTT_USER and MQTT_PASS."""
    username = _app_user()
    password = _env("MQTT_PASS")
    if not username or not password:
        _LOGGER.warning("MQTT_USER or MQTT_PASS is empty; the app has no broker login yet")
        return
    try:
        result = await asyncio.to_thread(add_login, username, password, True)
    except Exception:
        _LOGGER.exception("Could not create the app's Mosquitto login")
        return
    if result == "added":
        if await reload_mosquitto():
            await asyncio.sleep(1)
        else:
            _LOGGER.error("App login was written, but Mosquitto did not reload it")
    elif result == "error":
        _LOGGER.error("Could not create the app's Mosquitto login")
    else:
        _LOGGER.info("App Mosquitto login %s... is ready (%s)", username[:4], result)

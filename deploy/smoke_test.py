"""Smoke test for the bundled demo (`make demo-smoke`).

Exercises the full path with a MOCK LLM (no real key): start the platform API +
a mock OpenAI endpoint, provision a serve token, run the in-kernel serve loop
bound to a live agent, sign in via /v1/demo-login, then send a chat over the
playground WebSocket and assert the agent's reply streams back.

Exits 0 on PASS, non-zero on FAIL. Run it with the platform/api venv active
(uv run) so hexgate + fastapi + websockets resolve.
"""

from __future__ import annotations

import asyncio
import http.cookiejar
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ASIANF = Path(__file__).resolve().parent.parent
API_DIR = ASIANF / "platform" / "api"
DEPLOY = ASIANF / "deploy"
DB = API_DIR / "hexgate.db"
KEY_FILE = Path(os.environ.get("HEXGATE_SERVE_KEY_FILE", "/tmp/hexgate_smoke_key"))
DEFAULT_PROJECT_ID = "00000000-0000-0000-0000-000000000003"
BIN = Path(sys.executable).parent  # venv bin — uvicorn lives alongside python
API_PORT, MOCK_PORT = 8000, 9100

for f in (DB, KEY_FILE):
    f.unlink(missing_ok=True)

env = dict(os.environ)
env["HEXGATE_DEMO"] = "1"
env["HEXGATE_COOKIE_SECURE"] = "0"
env["HEXGATE_API_URL"] = f"http://127.0.0.1:{API_PORT}"
env["HEXGATE_ROOT"] = str(ASIANF)
env["HEXGATE_SERVE_KEY_FILE"] = str(KEY_FILE)
# Point the agent's OpenAI client at the mock.
env["OPENAI_BASE_URL"] = f"http://127.0.0.1:{MOCK_PORT}/v1"
env["OPENAI_API_BASE"] = f"http://127.0.0.1:{MOCK_PORT}/v1"
env["PYTHONPATH"] = os.pathsep.join([str(API_DIR), str(ASIANF), str(DEPLOY)])

_procs: list[subprocess.Popen] = []


def _spawn(cmd: list[str], cwd: Path) -> None:
    _procs.append(subprocess.Popen(cmd, cwd=str(cwd), env=env))


def _wait_http(url: str, timeout: float = 90) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except Exception:
            time.sleep(0.4)
    return False


async def main() -> bool:
    import websockets

    _spawn([str(BIN / "uvicorn"), "_mock_llm:app", "--port", str(MOCK_PORT)], DEPLOY)
    _spawn([str(BIN / "uvicorn"), "hexgate_api.main:app", "--port", str(API_PORT)], API_DIR)
    if not _wait_http(f"http://127.0.0.1:{MOCK_PORT}/docs"):
        print("❌ mock LLM did not start")
        return False
    if not _wait_http(f"http://127.0.0.1:{API_PORT}/v1/.well-known/keys"):
        print("❌ API did not start")
        return False
    print("✅ API + mock LLM up")

    sys.path.insert(0, str(API_DIR))
    sys.path.insert(0, str(DEPLOY))
    os.environ.update(env)

    from provision import provision_serve_token

    # provision uses asyncio.run internally → run it off this loop in a thread.
    KEY_FILE.write_text(await asyncio.to_thread(provision_serve_token))
    print("✅ serve key minted")

    import serve_manager
    from hexgate import create_agent

    agent, _ = create_agent(
        model="gpt-4o-mini", tools=[], system_prompt="be brief", name="demo_agent"
    )
    os.environ["OPENAI_API_KEY"] = "sk-mock-byok"  # set in env, as the notebook does
    serve_manager.apply(agent)  # in-kernel serve, live object
    await asyncio.sleep(2)
    print(f"✅ serve started in-kernel: {serve_manager.status()}")

    cj = http.cookiejar.CookieJar()
    urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj)).open(
        f"http://127.0.0.1:{API_PORT}/v1/demo-login"
    )
    cookie = "; ".join(f"{c.name}={c.value}" for c in cj)
    if "hexgate_session" not in cookie:
        print("❌ no session cookie from demo-login")
        return False
    print("✅ signed in via demo-login")

    uri = f"ws://127.0.0.1:{API_PORT}/v1/projects/{DEFAULT_PROJECT_ID}/chat"
    try:
        ws = await websockets.connect(uri, additional_headers={"Cookie": cookie})
    except TypeError:  # older websockets API
        ws = await websockets.connect(uri, extra_headers={"Cookie": cookie})

    online = False
    text = ""
    done = False
    async with ws:
        end = time.time() + 15
        while time.time() < end and not online:
            try:
                m = json.loads(await asyncio.wait_for(ws.recv(), timeout=2))
                if m.get("type") == "agent_online" and m.get("online"):
                    online = True
            except asyncio.TimeoutError:
                pass
        if not online:
            print("❌ agent never came online")
            return False
        print("✅ agent online")

        await ws.send(json.dumps({"type": "chat", "message": "hello"}))
        end = time.time() + 40
        while time.time() < end and not done:
            try:
                m = json.loads(await asyncio.wait_for(ws.recv(), timeout=3))
            except asyncio.TimeoutError:
                continue
            et = m.get("event_type")
            if et == "block_delta" and m.get("block_type") == "text":
                text += m.get("text", "")
            elif et == "run_end":
                done = True
                text = m.get("result", {}).get("message") or text
            elif et == "error":
                print(f"❌ error event: {m.get('message')}")
                return False

    print(f"assistant reply: {text!r}")
    return bool(online and done and text.strip())


def _cleanup() -> None:
    for p in _procs:
        p.terminate()
    try:
        import serve_manager

        serve_manager.stop()
    except Exception:
        pass
    for f in (DB, KEY_FILE):
        f.unlink(missing_ok=True)


if __name__ == "__main__":
    ok = False
    try:
        ok = asyncio.run(main())
    finally:
        _cleanup()
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)

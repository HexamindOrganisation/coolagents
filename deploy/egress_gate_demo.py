"""Hexgate egress-gate demo (marimo) — gate outbound network by policy, in code.

A code-only tour of the optional egress enforcement plane: no platform, no API
key, no YAML on disk. The policy is written with `PolicyBuilder` + `C`, and the
same policy both (1) decides hosts offline and (2) drives a *live* in-process
forward proxy that this notebook's own HTTP client is routed through — so you
watch a real request get allowed or refused at the network layer.

Run with `uv run --with marimo marimo edit deploy/egress_gate_demo.py`.
"""

import marimo

__generated_with = "0.23.10"
app = marimo.App(width="medium")


@app.cell
def _():
    import asyncio
    import inspect

    import httpx
    import marimo as mo

    from hexgate import HexgateContext, PolicyBuilder
    from hexgate.egress import NET_TOOL, egress_guard, tcp_egress_guard
    from hexgate.security.enforcer import build_enforcer
    from hexgate.security.policy_set import load_policy_set

    return (
        NET_TOOL,
        PolicyBuilder,
        HexgateContext,
        asyncio,
        build_enforcer,
        egress_guard,
        httpx,
        inspect,
        load_policy_set,
        mo,
        tcp_egress_guard,
    )


@app.cell
def _(mo):
    mo.md(
        """
        # 🌐 Hexgate — gating network egress

        Hexgate normally gates the **tool call** the model proposes. But a tool
        that runs `curl`, or an SDK that makes its own HTTP calls, can reach the
        network *without* the tool-argument policy seeing the real destination.

        The **egress proxy** closes that gap: it routes the process's outbound
        HTTP(S) through the *same* policy engine, mapped to a synthetic
        `net.http_request` tool. Network egress becomes **just another gated tool**.

        The same plane reaches beyond HTTP. A raw-TCP **reachability gate**
        (`net.tcp_connect`) decides database and broker connections by host and
        port before TLS starts. That's section 4.

        This demo is **code-only** — no platform, no API key, no YAML file. The
        policy is written in Python and drives a live in-process proxy.

        > **Tier 1 (this demo):** HTTPS is gated on the `CONNECT` host — visible in
        > plaintext before TLS begins. The tunnel relays ciphertext untouched; we
        > never decrypt. So constraints are on `args.host` / `args.scheme` /
        > `args.port`, not the path or body.
        """
    )
    return


@app.cell
def _(mo):
    mo.md("""## 1 · The policy, written in code""")
    return


@app.cell
def _(PolicyBuilder, load_policy_set):
    # Deny by default; allow HTTPS to two GitHub hosts — via the net_allow sugar,
    # which renders the host + scheme allowlist into ordinary constraints (shown
    # below as the YAML it produces). schemes defaults to HTTPS-only.
    def build_policy():
        return (
            PolicyBuilder(default="deny")
            .net_allow(hosts=["api.github.com", "raw.githubusercontent.com"])
            .build()
        )

    ps = load_policy_set(build_policy())  # a PolicySet with the policy as `default`
    return build_policy, ps


@app.cell
def _(build_policy, inspect, mo):
    import yaml as _yaml

    _src = inspect.getsource(build_policy)
    _rendered = _yaml.dump(
        build_policy().model_dump(exclude_defaults=True), sort_keys=False
    )
    mo.hstack(
        [
            mo.vstack([mo.md("**Written in Python**"), mo.md(f"```python\n{_src}```")]),
            mo.vstack(
                [mo.md("**Renders to YAML**"), mo.md(f"```yaml\n{_rendered}```")]
            ),
        ],
        widths="equal",
    )
    return


@app.cell
def _(mo):
    mo.md(
        """
        ## 2 · Decide hosts offline — not a single socket

        The policy engine decides an egress request the same way it decides a tool
        call: `(role, tool, args)`. No proxy, no network — just the verdict.
        """
    )
    return


@app.cell
def _(NET_TOOL, mo, ps):
    def _decide(host, scheme="https"):
        verdict = ps.evaluate(
            role="agent",
            tool=NET_TOOL,
            args={"host": host, "scheme": scheme, "port": 443},
        )
        return verdict.outcome.value

    _cases = [
        ("api.github.com", "https"),  # allowlisted
        ("raw.githubusercontent.com", "https"),  # allowlisted
        ("api.github.com", "http"),  # wrong scheme -> deny
        ("example.com", "https"),  # not allowlisted -> deny
        ("203.0.113.5", "https"),  # IP literal never matches host list -> deny
    ]
    _label = {"allow": "✅ allow", "deny": "❌ deny", "needs_approval": "🔶 approval"}
    _rows = ["| host | scheme | decision |", "|---|---|---|"]
    for _host, _scheme in _cases:
        _outcome = _decide(_host, _scheme)
        _rows.append(f"| `{_host}` | {_scheme} | {_label.get(_outcome, _outcome)} |")
    mo.md("\n".join(_rows))
    return


@app.cell
def _(mo):
    mo.md(
        """
        ## 3 · Now for real — through the live proxy

        Same policy, but this time it drives an in-process forward proxy. This
        notebook's `httpx` client is pointed at it (via `HTTP_PROXY`/`HTTPS_PROXY`,
        set by `egress_guard`), so the request below is **actually intercepted** at
        the network layer — allowed hosts connect, denied hosts get refused.
        """
    )
    return


@app.cell
def _(
    HexgateContext, build_enforcer, build_policy, egress_guard, httpx, load_policy_set
):
    async def probe(url):
        # A fresh enforcer per probe, with an observer that captures decisions.
        decisions = []
        enforcer = build_enforcer(
            load_policy_set(build_policy()),
            agent_name="egress-demo",
            decision_observer=decisions.append,
        )
        outcome = {}
        async with egress_guard(
            enforcer, HexgateContext(user_id="notebook", user_roles=["agent"])
        ):
            async with httpx.AsyncClient(timeout=10) as client:
                try:
                    response = await client.get(url)
                    outcome = {"ok": True, "status": response.status_code}
                except httpx.HTTPError as exc:
                    outcome = {"ok": False, "error": type(exc).__name__}
        return decisions, outcome

    return (probe,)


@app.cell
def _(mo):
    url_form = (
        mo.md("**URL** {url}")
        .batch(url=mo.ui.text(value="https://api.github.com/zen", full_width=True))
        .form(submit_button_label="▶ Send through the egress proxy")
    )
    url_form
    return (url_form,)


@app.cell
async def _(mo, probe, url_form):
    if url_form.value is None:
        _out = mo.callout(
            mo.md("Enter a URL and click **▶ Send through the egress proxy**."),
            kind="info",
        )
    else:
        _url = url_form.value["url"]
        _decisions, _outcome = await probe(_url)
        if _outcome.get("ok"):
            _result = mo.callout(
                mo.md(f"**Response `{_outcome['status']}`** — allowed through"),
                kind="success",
            )
        else:
            _result = mo.callout(
                mo.md(
                    f"**Blocked — `{_outcome.get('error', '?')}`** "
                    "(the proxy refused the connection)"
                ),
                kind="danger",
            )
        _decision = _decisions[0] if _decisions else None
        if _decision is not None:
            _host = (_decision.arguments or {}).get("host", "?")
            _lines = [
                f"Policy decision: **{_decision.outcome.value}** for host `{_host}`"
            ]
            if not _decision.allowed and _decision.reason:
                _lines.append(f"\n\nreason: {_decision.reason}")
            _decision_md = mo.md("".join(_lines))
        else:
            _decision_md = mo.md(
                "_(no decision captured — request never reached the proxy)_"
            )
        _out = mo.vstack([mo.md(f"`GET {_url}`"), _result, _decision_md])
    _out
    return


@app.cell
def _(mo):
    mo.md(
        """
        ## 4 · Beyond HTTP: the raw-TCP reachability gate

        A database driver opens a raw TCP socket and ignores `HTTP_PROXY`, so the
        HTTP proxy above never sees it. `net_tcp_allow` + `tcp_egress_guard` gate
        that connection by host and port, decided before any bytes flow (so before
        TLS), then tunnel it or drop it. Below, a local echo server stands in for a
        database: one policy allows its port, the other only allows `5432`.
        """
    )
    return


@app.cell
async def _(
    PolicyBuilder,
    HexgateContext,
    asyncio,
    build_enforcer,
    load_policy_set,
    mo,
    tcp_egress_guard,
):
    async def _mock_db():
        async def _handle(reader, writer):
            while data := await reader.read(1024):
                writer.write(b"reply:" + data)
                await writer.drain()
            writer.close()

        server = await asyncio.start_server(_handle, "127.0.0.1", 0)
        return server, server.sockets[0].getsockname()[1]

    async def _probe(policy, target):
        decisions = []
        enforcer = build_enforcer(
            load_policy_set(policy),
            agent_name="tcp-demo",
            decision_observer=decisions.append,
        )
        async with tcp_egress_guard(
            enforcer,
            HexgateContext(user_id="notebook", user_roles=["agent"]),
            target=target,
        ) as proxy:
            try:
                reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
                writer.write(b"SELECT 1")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(100), timeout=3)
                writer.close()
                outcome = data.decode() if data else "connection dropped"
            except (OSError, asyncio.TimeoutError):
                outcome = "connection refused"
        return (decisions[0] if decisions else None), outcome

    _db, _port = await _mock_db()
    try:
        _allow = (
            PolicyBuilder(default="deny")
            .net_tcp_allow(hosts=["127.0.0.1"], ports=[_port])
            .build()
        )
        _deny = (
            PolicyBuilder(default="deny")
            .net_tcp_allow(hosts=["127.0.0.1"], ports=[5432])
            .build()
        )
        _da, _ra = await _probe(_allow, ("127.0.0.1", _port))
        _dd, _rd = await _probe(_deny, ("127.0.0.1", _port))
    finally:
        _db.close()
        await _db.wait_closed()

    _mark = {"allow": "✅ allow", "deny": "❌ deny", "needs_approval": "🔶 approval"}
    mo.md(
        "\n".join(
            [
                f"| policy | decision on `127.0.0.1:{_port}` | result |",
                "|---|---|---|",
                f"| `net_tcp_allow(ports=[{_port}])` | "
                f"{_mark.get(_da.outcome.value) if _da else '?'} | `{_ra}` |",
                "| `net_tcp_allow(ports=[5432])` | "
                f"{_mark.get(_dd.outcome.value) if _dd else '?'} | `{_rd}` |",
            ]
        )
    )
    return


if __name__ == "__main__":
    app.run()

# /// script
# requires-python = ">=3.13"
# dependencies = ["marimo", "hexgate"]
# ///
"""Hexgate guards, live — write a guard, then watch it fire across every framework.

Run it:  `marimo edit examples/marimo_guards_demo.py`
Everything runs offline: no API keys, no LLM calls — guards are exercised directly
against the tool layer, which is exactly what runs on a real agent call.
"""

import marimo

__generated_with = "0.9.0"
app = marimo.App(width="medium")


@app.cell
def _():
    import marimo as mo

    return (mo,)


@app.cell
def _(mo):
    mo.md(
        r"""
        # Hexgate guards, live

        A **guard** is a small function you attach *before* and *after* a tool call to
        **observe** it, **rewrite its arguments**, or **refuse** it — the open extension
        point next to the policy check (`decide`).

        ```
          the agent wants to call a tool
                    │
          1. before-guards   look at the arguments; tweak them, or refuse
                    │
          2. decide          allow / deny / needs-approval  (the policy)
                    │
          3. run the tool
                    │
          4. after-guards    look at the result; refuse to pass it back
        ```

        This notebook: **write a guard**, use the **official secret plugins**, then
        watch the same guards fire through **every adapter** — native Hexgate,
        LangChain, OpenAI Agents, Google ADK, and Pydantic AI.
        """
    )
    return


@app.cell
def _():
    # Shared setup — the whole guard toolkit, plus a fake secret and an allow-all
    # policy so the demo runs with no keys and no platform.
    from hexgate.guards import (
        Halt,
        Proceed,
        ToolCall,
        ToolOutcome,
        after_tool,
        before_tool,
        build_pipeline,
    )
    from hexgate.plugins import (
        scan_secrets,
        secret_guard,
        secret_redactor,
        secret_watch,
    )
    from hexgate.runtime import HexgateContext
    from hexgate.security import AgentPolicy, PolicySet
    from hexgate.security.enforcer import PolicyEnforcer
    from hexgate.security.policy_set import DEFAULT_ROLE_NAME

    SECRET = "AKIAIOSFODNN7EXAMPLE"  # a fake AWS access key

    def allow_all() -> PolicyEnforcer:
        """An enforcer that permits every tool, so the demo shows the *guards*."""
        engine = PolicySet(
            {
                DEFAULT_ROLE_NAME: AgentPolicy.model_validate(
                    {"default_policy": {"mode": "allow"}}
                )
            }
        )
        return PolicyEnforcer(engine, agent_name="demo")

    return (
        Halt,
        HexgateContext,
        Proceed,
        SECRET,
        ToolCall,
        ToolOutcome,
        after_tool,
        allow_all,
        before_tool,
        build_pipeline,
        scan_secrets,
        secret_guard,
        secret_redactor,
        secret_watch,
    )


@app.cell
def _(mo):
    mo.md(
        r"""
        ## 1 · Writing a guard

        You write a guard with `@before_tool` or `@after_tool`. It receives the
        `ToolCall` (and, after, the `ToolOutcome`) and returns one of:

        | return | meaning |
        | --- | --- |
        | `None` / `Proceed()` | carry on unchanged |
        | `Proceed(args=...)` | continue with **rewritten arguments** (before only) |
        | `Halt(reason=...)` | **refuse**; the model sees a safe error, not a result |

        Below we call the guards **directly** on a `ToolCall` — the clearest way to see
        what a guard receives and returns.
        """
    )
    return


@app.cell
def _(Halt, before_tool, scan_secrets):
    # A GLOBAL before-guard — no tool_names, so it runs on every tool.
    @before_tool
    def block_secrets(call):
        if scan_secrets(call.args):
            return Halt(reason="Refused: a credential was found; remove it and resend.")
        return None  # None means "carry on"

    return (block_secrets,)


@app.cell
def _(Halt, before_tool):
    # A TOOL-SPECIFIC before-guard — tool_names scopes it to one tool.
    @before_tool(tool_names=["wire_transfer"])
    def cap_amount(call):
        if call.args.get("amount", 0) > 1000:
            return Halt(
                reason="Transfers over 1000 need a manager. Lower it or escalate."
            )
        return None

    return (cap_amount,)


@app.cell
def _(Proceed, before_tool):
    # A before-guard that REWRITES the arguments — the cleaned call is what runs.
    @before_tool
    def drop_debug_flag(call):
        if "debug" in call.args:
            return Proceed(args={k: v for k, v in call.args.items() if k != "debug"})
        return None

    return (drop_debug_flag,)


@app.cell
def _(Halt, after_tool, scan_secrets):
    # An AFTER-guard — sees the result and can withhold it from the model.
    @after_tool
    def block_leaky_result(call, outcome):
        if outcome.ok and scan_secrets(outcome.value):
            return Halt(reason="The tool's output was withheld by policy.")
        return None

    # An OBSERVE after-guard — fail-open watcher; can log but never halt or rewrite.
    @after_tool(observe=True)
    def audit(call, outcome):
        print(f"[audit] {call.tool_name} ok={outcome.ok}")

    return audit, block_leaky_result


@app.cell
def _(
    SECRET,
    ToolCall,
    ToolOutcome,
    block_leaky_result,
    block_secrets,
    cap_amount,
    drop_debug_flag,
    mo,
):
    _rows = [
        (
            "global before · secret present",
            block_secrets(ToolCall("send", {"body": f"key {SECRET}"})),
        ),
        ("global before · clean", block_secrets(ToolCall("send", {"body": "hello"}))),
        (
            "tool-specific · over limit on wire_transfer",
            cap_amount(ToolCall("wire_transfer", {"amount": 5000})),
        ),
        (
            "tool-specific · scope check",
            f"applies to wire_transfer={cap_amount.applies('wire_transfer')}, to send={cap_amount.applies('send')}",
        ),
        (
            "rewrite · strip debug flag",
            drop_debug_flag(ToolCall("query", {"q": "x", "debug": True})),
        ),
        (
            "after · secret in result",
            block_leaky_result(
                ToolCall("read", {}), ToolOutcome(ok=True, value={"k": SECRET})
            ),
        ),
    ]
    mo.md(
        "**Calling the guards directly:**\n\n"
        + "\n".join(f"- **{label}** → `{result}`" for label, result in _rows)
    )
    return


@app.cell
def _(mo):
    mo.md(
        r"""
        ## 2 · The official plugins

        `hexgate.plugins` ships ready-made guards over one secret detector. Register
        them like any guard; they name the credential's **category and field**, never
        the value.

        - `secret_guard` — before / **halt** on a credential
        - `secret_redactor` — before / **strip** the credential, run the cleaned call
        - `secret_watch` — after / **observe** (logs a leak in the result)
        """
    )
    return


@app.cell
def _(SECRET, ToolCall, mo, secret_guard, secret_redactor):
    _guard = secret_guard(ToolCall("send_email", {"auth": {"token": SECRET}}))
    _redact = secret_redactor(ToolCall("send_email", {"auth": {"token": SECRET}}))
    mo.md(
        f"""
        **`secret_guard`** halts with a value-free reason:

        > {_guard.reason}

        **`secret_redactor`** rewrites the arguments in place:

        - args → `{_redact.args}`
        - modification → `{_redact.modification.summary}`
        """
    )
    return


@app.cell
def _(mo):
    mo.md(
        r"""
        ## 3 · The same guards, across every framework

        A guard is framework-agnostic. Below, one pipeline — `[secret_redactor,
        block_secrets]` — is attached at each framework's tool layer, then the tool is
        invoked with a secret in its arguments. In every case the redactor strips the
        secret **before** the tool runs, so the tool sees `[REDACTED:…]`. This is
        exactly the pipeline that executes on a real agent call.
        """
    )
    return


@app.cell
def _(block_secrets, build_pipeline, secret_redactor):
    pipe = build_pipeline([secret_redactor, block_secrets])
    return (pipe,)


@app.cell
async def _(HexgateContext, SECRET, mo, pipe):
    # Native Hexgate + LangChain share the GuardedTool layer (create_agent and
    # wrap_langchain_agent both install it). Here we wrap a tool with guards only.
    from langchain_core.tools import tool as _lc_tool

    from hexgate.adapters.langchain.tools import GuardedTool as _GuardedTool

    @_lc_tool("echo")
    def _echo(text: str) -> str:
        """Echo the input."""
        return f"tool ran with: {text}"

    _guarded = _GuardedTool.wrap(_echo, pipeline=pipe)
    async with HexgateContext(user_id="demo"):
        _out = _guarded._run(text=f"my key is {SECRET}")
    mo.md(
        f"**Native / LangChain** (`create_agent(guards=…)`, `wrap_langchain_agent(guards=…)`):\n\n> {_out}"
    )
    return


@app.cell
async def _(HexgateContext, SECRET, allow_all, mo, pipe):
    import json as _json

    from agents import FunctionTool as _FunctionTool

    from hexgate.adapters.openai.tools import wrap_tool as _wrap_tool

    async def _invoke(ctx, raw):
        return f"tool ran with: {raw}"

    _tool = _FunctionTool(
        name="echo",
        description="echo",
        params_json_schema={
            "type": "object",
            "properties": {"text": {"type": "string"}},
        },
        on_invoke_tool=_invoke,
    )
    _wrapped = _wrap_tool(_tool, allow_all(), pipeline=pipe)
    async with HexgateContext(user_id="demo"):
        _out = await _wrapped.on_invoke_tool(
            None, _json.dumps({"text": f"my key is {SECRET}"})
        )
    mo.md(
        f"**OpenAI Agents** (`wrap_openai_agent(guards=…)`, `HexgateRunner(guards=…)`):\n\n> {_out}"
    )
    return


@app.cell
async def _(HexgateContext, SECRET, allow_all, mo, pipe):
    from google.adk.tools import FunctionTool as _GFunctionTool

    from hexgate.adapters.google.tools import wrap_tool as _g_wrap_tool

    def _echo(text: str) -> str:
        return f"tool ran with: {text}"

    _echo.__name__ = "echo"
    _wrapped = _g_wrap_tool(_GFunctionTool(func=_echo), allow_all(), pipeline=pipe)
    async with HexgateContext(user_id="demo"):
        _out = await _wrapped.run_async(
            args={"text": f"my key is {SECRET}"}, tool_context=None
        )
    mo.md(
        f"**Google ADK** (`wrap_google_agent(guards=…)`, `HexgateRunner(guards=…)`):\n\n> {_out}"
    )
    return


@app.cell
async def _(HexgateContext, SECRET, allow_all, mo, pipe):
    from pydantic_ai.tools import Tool as _Tool

    from hexgate.adapters.pydantic_ai.tools import wrap_tool as _p_wrap_tool

    def _echo(text: str) -> str:
        return f"tool ran with: {text}"

    _wrapped = _p_wrap_tool(_Tool(_echo, name="echo"), allow_all(), pipeline=pipe)
    async with HexgateContext(user_id="demo"):
        _out = await _wrapped.function_schema.call(
            {"text": f"my key is {SECRET}"}, None
        )
    mo.md(f"**Pydantic AI** (`wrap_pydantic_agent(guards=…)`):\n\n> {_out}")
    return


@app.cell
def _(mo):
    mo.md(
        r"""
        ## Wiring guards into your real agent

        The tool layer above is what runs on a live call. In your own code you just pass
        `guards=[...]` to whichever surface you use:

        ```python
        from hexgate import create_agent
        from hexgate.plugins import secret_guard, secret_watch

        # Native
        agent, _ = create_agent(model="gpt-5.4", tools=[...],
                                guards=[secret_guard, secret_watch])

        # Adapters (same argument everywhere)
        wrap_langchain_agent(..., guards=[secret_guard])
        wrap_pydantic_agent(agent=..., guards=[secret_guard])
        HexgateRunner(guards=[secret_guard])          # OpenAI Agents, Google ADK
        ```

        See the [Guards concept page](/concepts/guards) for the full contract
        (halt-message safety, the fail-closed vs observe tiers, and more).
        """
    )
    return


if __name__ == "__main__":
    app.run()

"""Hexgate live-demo notebook (marimo) — Google ADK edition.

Twin of ``openai_demo_notebook.py`` / ``demo_notebook.py``, but the agent is a
raw Google ADK ``Agent``. It exercises the Google serve path end to end:
``serve_manager`` runs the ``hexgate serve`` loop bound to the live ``Agent``,
``hexgate serve`` dispatches on the manifest framework to the Google runtime
(``GoogleServeDriver`` owns the ADK session + SSE streaming), and every turn
streams through the Google → hexgate ``StreamEvent`` normalizer to the dashboard
Playground.

BYOK is an OpenAI key: the ADK agent runs on OpenAI via ``LiteLlm``. Your key
lives only in this throwaway container and is never written to disk. Run by
boot.py via ``marimo edit``.
"""

import marimo

__generated_with = "0.23.10"
app = marimo.App(width="medium")


@app.cell
def _():
    import sys
    from pathlib import Path

    import marimo as mo

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import serve_manager

    return Path, mo, serve_manager


@app.cell
def _(mo):
    mo.md("""
    # 🛡️ Hexgate — run a live **Google ADK** agent

    A **throwaway sandbox** — everything vanishes when it scales down. The
    Google-framework twin of the native demo: same gate, same dashboard, a
    `google.adk.agents.Agent` instead of a hexgate agent.

    1. **Define your tools** (plain Python functions).
    2. **Define your agent** (a factory — built on Start, after your key).
    3. **Enter your OpenAI key and start it** (the ADK agent runs on OpenAI via LiteLlm).
    4. **Open the playground** to chat and watch policy decisions stream.
    """)
    return


@app.cell
def _(mo):
    mo.md("""
    ## 1 · Define your tools
    """)
    return


@app.cell
def _():
    # Plain Python functions — ADK wraps them as tools. The function name is the
    # tool name the policy references below.
    def get_order_status(order_id: str) -> str:
        """Look up the delivery status of an order by its id."""
        return f"Order {order_id}: shipped, arriving Tuesday."

    def refund_order(order_id: str, amount: float) -> str:
        """Issue a refund of `amount` USD for `order_id`. A side-effecting tool."""
        return f"Refunded ${amount:.2f} for order {order_id}."

    TOOLS = [get_order_status, refund_order]
    return (TOOLS,)


@app.cell
def _(mo):
    mo.md("""
    ## 2 · Define your agent
    """)
    return


@app.cell
def _(TOOLS):
    # A factory — built on Start (step 3), after your key. The `name` is the
    # manifest name and the policy lookup key on the platform.
    from google.adk.agents import Agent
    from google.adk.models.lite_llm import LiteLlm

    def build_agent():
        return Agent(
            name="demo_google_agent",
            model=LiteLlm(model="openai/gpt-4o-mini"),
            instruction=(
                "You are a customer support agent. Help with orders and refunds. "
                "Confirm details before issuing a refund."
            ),
            tools=TOOLS,
        )

    return (build_agent,)


@app.cell
def _(mo):
    mo.md("""
    ## 3 · Add your OpenAI key & start
    """)
    return


@app.cell
def _(mo):
    api_key = mo.ui.text(kind="password", placeholder="sk-...", full_width=True)
    start = mo.ui.run_button(label="▶ Start agent")
    mo.vstack([mo.md("**OpenAI API key**"), api_key, start])
    return api_key, start


@app.cell
def _(api_key, build_agent, mo, serve_manager, start):
    # serve_manager is framework-agnostic — build_runtime_from_local_agent
    # dispatches on the manifest framework and builds the Google runtime.
    import os
    import time

    if start.value:
        if not api_key.value:
            out = mo.md("⚠️ **Enter your OpenAI key above**, then click Start.")
        else:
            os.environ["OPENAI_API_KEY"] = api_key.value  # BYOK
            agent = build_agent()
            serve_manager.apply(agent)
            time.sleep(3)  # let it build the runtime, auto-register + dial /v1/serve
            st = serve_manager.status()
            if st == "running":
                out = mo.md(
                    f"✅ **Agent running** (key `…{api_key.value[-4:]}`). "
                    "Open the playground below."
                )
            elif st.startswith("error"):
                out = mo.md(f"❌ **Failed to start:** `{st}`")
            else:
                out = mo.md(
                    f"⏳ **{st}** — give it a few seconds and click Start again."
                )
    else:
        out = mo.md(
            f"Agent status: **{serve_manager.status()}** — "
            "enter your key above and click **Start agent**."
        )
    out
    return


@app.cell
def _(mo):
    mo.md("""
    ## The policy that governs it

    Keyed by the agent name (`demo_google_agent`) — view and edit it live in the
    Playground's **Policies** tab.

    ```yaml
    version: 1

    default_policy:
      mode: deny

    tools:
      get_order_status:
        mode: allow
      refund_order:
        mode: approval_required
        constraints:
          - args.amount <= 100
    ```

    A status lookup **runs**, a small refund **pauses for approval**, and a
    refund over $100 is **denied** — enforced by the ADK `HexgateRunner`, not
    the model.
    """)
    return


@app.cell
def _(mo):
    mo.md("""
    ## 4 · Open the playground
    """)
    return


@app.cell
def _(Path, mo):
    dash_url = Path("/tmp/hexgate_dash_url").read_text().strip().rstrip("/")
    login_url = f"{dash_url}/v1/demo-login"

    mo.md(
        f"""
        ### [▶ Chat with your agent →]({login_url})

        Opens the dashboard signed in. Send a message and watch the text, tool
        calls, and **policy decisions** stream live from the Google agent.
        """
    )
    return


@app.cell
def _():
    return


if __name__ == "__main__":
    app.run()

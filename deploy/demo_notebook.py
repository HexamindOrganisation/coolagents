"""Hexgate live-demo notebook (marimo) — define tools + agent, then run it.

The landing UI for a disposable demo container. Read top to bottom:
  1. define your tools,
  2. define your agent,
  3. enter your OpenAI key and start it,
  4. open the dashboard playground to chat.

The agent runs in-kernel (serve_manager runs the `hexgate serve` loop bound to
the live `agent` object) and streams to the dashboard. BYOK: your key lives only
in this throwaway container and is never written to disk.

Run by boot.py via `marimo edit`.
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
    # 🛡️ Hexgate — define & run a live agent

    A **throwaway sandbox** — everything vanishes when it scales down.

    1. **Define your tools** (real Python).
    2. **Define your agent** (a factory — built on Start, after your key).
    3. **Enter your OpenAI key and start it.**
    4. **Open the playground** to chat and watch policy decisions stream.

    Edit the tools/agent cells anytime, then click **Start** again to reload.
    """)
    return


@app.cell
def _(mo):
    # A picture of the one idea: every tool call detours through the gate, which
    # answers allow / deny / approval from the policy + the caller's role.
    _diagram = mo.mermaid(
        """
        flowchart LR
            You["🧑 you<br/>define agent + tools"] --> Agent["🤖 agent"]
            Agent -->|"tool call + args"| Gate
            subgraph HG ["🛡️ hexgate"]
                Gate["PolicyEnforcer"] --> Q{"role +<br/>args ok?"}
            end
            Q -->|allow| Tool["🔧 tool runs"]
            Q -->|deny| Blk["⛔ blocked"]
            Q -->|approval| Human["🙋 you approve<br/>in the Playground"]
            Human -->|approved| Tool
        """
    )
    mo.vstack(
        [
            mo.md("## How hexgate works"),
            _diagram,
            mo.md(
                "Your agent runs behind the **gate**: every tool call is checked "
                "against a **policy** — the caller's **role** and the call's "
                "**arguments** — and comes back **allow / deny / approval** before "
                "it runs. The policy lives on the platform; you watch decisions "
                "and approve them live in the dashboard **Playground**."
            ),
        ]
    )
    return


@app.cell
def _(mo):
    mo.md("""
    ## 1 · Define your tools
    """)
    return


@app.cell
def _():
    # Plain LangChain tools — edit / add freely, then re-run this cell. (Built-ins
    # exist too: `from hexgate.tools import read_file, write_file, bash, ...`.
    # web_search / fetch moved to examples/tools/ — import them from there.)
    from langchain_core.tools import tool

    @tool
    def get_order_status(order_id: str) -> str:
        """Look up the delivery status of an order by its id."""
        return f"Order {order_id}: shipped, arriving Tuesday."

    @tool
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
    # A factory — the actual agent is built on Start (step 3), AFTER your OpenAI
    # key is in env. create_agent() eagerly instantiates the chat model when
    # passed a string, and ChatOpenAI validates the key at construction, so the
    # build must happen post-key. Edit model / prompt / tools here, then click
    # Start to (re)build and reload it into the playground.
    from hexgate import create_agent

    def build_agent():
        return create_agent(
            model="gpt-4o-mini",
            tools=TOOLS,
            system_prompt=(
                "You are a customer support agent. Help with orders and refunds. "
                "Confirm details before issuing a refund."
            ),
            name="demo_agent",
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
    # Value is live as you type (no Enter needed); the button starts the agent.
    # The key lives only in the running kernel — never written to this file.
    api_key = mo.ui.text(kind="password", placeholder="sk-...", full_width=True)
    start = mo.ui.run_button(label="▶ Start agent")
    mo.vstack([mo.md("**OpenAI API key**"), api_key, start])
    return api_key, start


@app.cell
def _(api_key, build_agent, mo, serve_manager, start):
    # Fires on button click: set the key in the env, build the agent (must happen
    # after the key is set — see the step-2 cell), (re)start the in-kernel serve
    # loop bound to that live agent, then report the REAL status so you see it
    # actually connected.
    import os
    import time

    if start.value:
        if not api_key.value:
            out = mo.md("⚠️ **Enter your OpenAI key above**, then click Start.")
        else:
            os.environ["OPENAI_API_KEY"] = api_key.value  # BYOK
            agent, _handler = build_agent()
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

    A policy is a small YAML file: **default-deny**, then per-tool rules with
    optional **argument constraints**. Here's one for the tools above — view and
    edit it live in the Playground's **Policies** tab, and the next message obeys
    it.

    ```yaml
    version: 1

    default_policy:
      mode: deny                 # nothing runs unless a rule allows it

    tools:
      get_order_status:
        mode: allow              # safe read — always allowed

      refund_order:
        mode: approval_required  # side-effecting — a human approves it
        constraints:
          - args.amount <= 100   # ...and only up to $100; larger is denied
    ```

    So a status lookup just **runs**, a small refund **pauses for your approval**
    in the Playground, and a refund over $100 is **denied**.
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
    # Dashboard URL written by boot.py (the public tunnel, or localhost in dev).
    # /v1/demo-login signs the visitor in, then redirects to /playground.
    dash_url = Path("/tmp/hexgate_dash_url").read_text().strip().rstrip("/")
    login_url = f"{dash_url}/v1/demo-login"

    mo.md(
        f"""
        ### [▶ Chat with your agent →]({login_url})

        Opens the dashboard in a new tab, signed in. Send a message and watch the
        reasoning, tool calls, and **policy decisions** (allow / deny / approval)
        stream live. Edit the policy in the **Policies** tab — the next message
        picks it up.
        """
    )
    return


@app.cell
def _():
    return


if __name__ == "__main__":
    app.run()

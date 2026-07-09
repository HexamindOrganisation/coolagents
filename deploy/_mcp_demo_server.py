"""Tiny FastMCP server for the MCP-gate marimo demo (deploy/mcp_gate_demo.py).

Kept as its own file (not inline in the notebook) so marimo's file-format
round-tripping can't strip it. The notebook spawns it over stdio:

    python deploy/_mcp_demo_server.py

Exposes three tools chosen to map cleanly onto policy outcomes:
  * compute_tip   — pure math, safe                → allow (arg-gated)
  * read_secret   — pretends to read a secret      → deny
  * send_invoice  — pretends to have a side effect → approval_required
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

server = FastMCP("demo")


@server.tool(description="Compute the tip on a bill amount (USD).")
def compute_tip(amount: float, percent: float = 18.0) -> str:
    tip = round(amount * percent / 100, 2)
    return f"tip on ${amount:.2f} at {percent}% = ${tip:.2f}"


@server.tool(description="Read a stored secret by key (DEMO — never call for real).")
def read_secret(key: str) -> str:
    return f"secret['{key}'] = hunter2"  # fake; demo only


@server.tool(description="Send an invoice for an order. Returns the queued id.")
def send_invoice(order_id: str, amount: float) -> str:
    return f"queued invoice for {order_id} (${amount:.2f}) — id=INV-12345"


if __name__ == "__main__":
    server.run("stdio")

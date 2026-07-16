"""Fake Google Docs MCP server for the gates demo (deploy/gates-demo/notebook.py).

Stands in for a real third-party MCP server (e.g. an official Google Docs one)
so the demo has no external dependency and no OAuth. The notebook spawns it over
stdio:

    python deploy/gates-demo/gdocs_mcp_server.py

The point of the demo is that we do NOT control this server — it decides which
tools to expose; hexgate's policy decides what our agent may actually call. The
tools are chosen to exercise the constraint DSL (arg values, list quantifiers,
counts, prefixes), not to be a faithful Docs API.

Its own file (not inline in the notebook) so marimo's format round-tripping
can't strip it.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

server = FastMCP("gdocs")

# A tiny in-memory corpus. "CONF-" ids are confidential — the policy blocks
# reads of them for everyone but admins.
_DOCS = {
    "DOC-101": {"title": "Q3 launch plan", "body": "Ship the gate on the 14th."},
    "DOC-102": {"title": "Onboarding checklist", "body": "Laptop, badge, VPN."},
    "CONF-900": {"title": "Acquisition terms", "body": "Project Falcon — $42M."},
}


@server.tool(description="Search docs by a keyword in the title. Read-only.")
def search_docs(query: str) -> str:
    hits = [
        f"{doc_id}: {d['title']}"
        for doc_id, d in _DOCS.items()
        if query.lower() in d["title"].lower()
    ]
    return "\n".join(hits) if hits else f"no docs match {query!r}"


@server.tool(description="Read a document's full body by id.")
def read_doc(doc_id: str) -> str:
    doc = _DOCS.get(doc_id)
    return f"{doc['title']}\n\n{doc['body']}" if doc else f"no such doc: {doc_id}"


@server.tool(description="Create a new doc in a folder. Returns the new id.")
def create_doc(title: str, folder: str = "Drafts") -> str:
    return f"created '{title}' in {folder} — id=DOC-{len(_DOCS) + 100}"


@server.tool(
    description="Share a doc with recipients at a given role (viewer/editor/owner)."
)
def share_doc(doc_id: str, recipients: list[str], role: str = "viewer") -> str:
    return f"shared {doc_id} with {len(recipients)} recipient(s) as {role}"


@server.tool(description="Export a doc by POSTing it to an external URL.")
def export_doc(doc_id: str, url: str) -> str:
    return f"exported {doc_id} to {url}"


@server.tool(description="Permanently delete a doc. Destructive — needs confirm=true.")
def delete_doc(doc_id: str, confirm: bool = False) -> str:
    return (
        f"deleted {doc_id}"
        if confirm
        else f"refused: pass confirm=true to delete {doc_id}"
    )


if __name__ == "__main__":
    server.run("stdio")

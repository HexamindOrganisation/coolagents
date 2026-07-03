"""Module-scope variant of the ``repo_operator`` agent for ``hexgate register``.

``bash_file_agents.py`` defines the agent through a ``build_repo_operator``
factory so callers can pick a workspace, model, and session at runtime. The
CLI's register command needs a ready-built agent object reachable as
``module:attribute`` instead, so this file calls the factory once at import
time with default arguments and exposes the result as ``agent``:

    hexgate register --agent examples.bash_file_demo_agent:agent
"""

from __future__ import annotations

from examples.bash_file_agents import build_repo_operator

agent, _handler = build_repo_operator()
# build_repo_operator leaves the HexgateAgent unnamed because the same factory
# is registered under "repo_operator" in the in-process loader (see
# bash_file_agents.py). The CLI register path needs a name on the manifest, so
# we tag this module-scope instance with the loader name.
agent.name = "repo_operator"

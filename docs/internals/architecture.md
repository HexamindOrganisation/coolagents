# `hexgate` Structure

> ⚠️ Status: STALE — predates the multi-adapter + platform refactor. It still describes a small single-agent LangChain demo (`hexgate/demo.py`, `hexgate/setup.py`, two tools) that no longer reflects the codebase. Do not trust paths or flow here until refreshed.

This document summarizes how `hexgate` is structured, how the runtime flows, and what each file is responsible for.

## High-Level Shape

`hexgate` is a small LangChain-based agent runtime with:

- one demo entrypoint
- one agent factory
- one settings/bootstrap layer
- two tools: `web_search` and `fetch`
- one tracing wrapper for Langfuse
- one small async retry utility

The runtime flow is:

1. `hexgate/demo.py` starts the demo.
2. `hexgate/setup.py` loads `.env` and validates required keys.
3. `hexgate/agent/factory.py` builds the agent and Langfuse handler.
4. The agent uses the system prompt from `hexgate/prompts/agent_system.md`.
5. The agent can call `hexgate/tools/websearch.py` and `hexgate/tools/fetch.py`.
6. Tracing is handled through `hexgate/tracing/langfuse.py`.

## Directory Layout

```text
hexgate/
├── pyproject.toml
├── structure.md
└── hexgate/
    ├── __init__.py
    ├── demo.py
    ├── setup.py
    ├── agent/
    │   ├── __init__.py
    │   └── factory.py
    ├── config/
    │   ├── __init__.py
    │   └── settings.py
    ├── prompts/
    │   └── agent_system.md
    ├── tools/
    │   ├── __init__.py
    │   ├── fetch.py
    │   └── websearch.py
    ├── tracing/
    │   ├── __init__.py
    │   └── langfuse.py
    └── utils/
        ├── __init__.py
        └── retry.py
```

## Top-Level Files

### `pyproject.toml`

This is the package manifest. It defines the project metadata, runtime dependencies, and dev dependencies.

Key snippet:

```toml
[project]
name = "hexgate"
version = "0.1.0"
requires-python = ">=3.13"
dependencies = [
    "deepagents",
    "httpx>=0.28.1",
    "langchain-openai",
    "langchain-core",
    "langfuse",
    "pydantic>=2.12.4",
    "python-dotenv>=1.1.1",
]
```

Meaning:

- `langchain` provides the agent runtime
- `httpx` is used by the tools
- `langchain-core` provides the `@tool` decorator
- `langfuse` handles tracing
- `python-dotenv` loads `.env`

## Package Files

### `hexgate/__init__.py`

This marks `hexgate/` as a Python package.

Key snippet:

```python
"""Hexgate package."""
```

Right now it is intentionally minimal.

### `hexgate/setup.py`

This is the bootstrap layer. It loads environment variables and returns a validated `Settings` object.

Key snippet:

```python
def bootstrap(env_file: str = ".env", *, local_only: bool = False) -> Settings:
    env_path = Path(__file__).parent.parent / env_file
    load_dotenv(env_path, override=False)
    audit.configure()
    return Settings.from_env()
```

Role:

- resolve the `.env` path relative to the repo
- load env vars into the process (shell wins over `.env`)
- create typed settings

Provider keys (OpenAI / Linkup / Tavily) are **not** validated here — each is
optional and only raises at use-time by the tool or model provider that reads
it, so an agent that uses none of them boots without any of those keys set.

### `hexgate/demo.py`

This is the runnable demo entrypoint. It shows the happy path for the first agent.

Key snippet:

```python
settings = bootstrap()
agent, handler = create_agent(settings, session_id="demo-session")

async for event in stream_agent(agent, handler, query):
    print(event)
```

Role:

- initialize the app
- create the agent and trace handler
- send one hardcoded demo query
- print streaming updates
- print the Langfuse trace URL if tracing is active

### `hexgate/agent/__init__.py`

This marks the `agent/` directory as a package. It currently has no extra logic.

### `hexgate/agent/factory.py`

This is the core composition file. It wires together the model, tools, prompt, and tracing.

Key snippets:

```python
tools = [web_search, fetch]
agent = create_deep_agent(
    model=settings.model,
    tools=tools,
    system_prompt=_load_system_prompt(),
)
```

```python
handler = get_langfuse_handler(
    session_id=session_id,
    user_id=user_id,
    tags=["hexgate", settings.search_engine, settings.model],
)
```

```python
return await agent.ainvoke(
    {"messages": [{"role": "user", "content": query}]},
    config=get_langfuse_runnable_config(handler),
)
```

Responsibilities:

- read the system prompt from disk
- build the agent
- attach the two custom tools
- create a Langfuse callback handler
- provide both non-streaming and streaming invocation helpers

This file is effectively the runtime assembly point.

### `hexgate/config/__init__.py`

This marks the config folder as a package.

### `hexgate/config/settings.py`

This defines the typed runtime settings model and validates required API keys.

Key snippets:

```python
@dataclass(slots=True)
class Settings:
    openai_api_key: str | None
    linkup_api_key: str | None
    tavily_api_key: str | None
    langfuse_public_key: str | None
    langfuse_secret_key: str | None
```

```python
langfuse_host=os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com"),
model=os.getenv("HEXGATE_DEFAULT_MODEL", "openai:gpt-5.4"),
search_engine=os.getenv("HEXGATE_DEFAULT_SEARCH_ENGINE", "linkup"),
```

Responsibilities:

- gather all env-based configuration in one place
- provide defaults for model and Langfuse host
- leave every provider key optional — missing keys resolve to `None` and are
  enforced lazily by whatever reads them, not eagerly at bootstrap

### `hexgate/prompts/agent_system.md`

This is the agent’s system prompt, kept outside Python so it is easy to edit separately.

Key snippet:

```md
Available custom tools:
- `web_search(query, max_results=8, depth="standard")`
- `fetch(url, extract_depth="basic")`
```

It tells the model:

- what role it has
- when to use tools
- what tools exist
- how concise and direct the answers should be

Keeping prompts in Markdown makes prompt iteration cleaner than embedding long strings in Python.

### `hexgate/tools/__init__.py`

This marks the tools folder as a package.

### `hexgate/tools/websearch.py`

This implements a Linkup-backed search tool exposed to the agent.

Key snippets:

```python
@tool
@observe(name="linkup_web_search")
@async_retry(retries=3, delay_ms=1000, exceptions=(httpx.HTTPError,))
async def web_search(
    query: str,
    max_results: int = 8,
    depth: str = "standard",
) -> dict:
```

```python
response = await client.post(url, headers=headers, json=payload)
response.raise_for_status()
```

```python
normalized = [
    {
        "title": result.get("name", ""),
        "url": result.get("url", ""),
        "content": result.get("content", ""),
        "favicon": result.get("favicon"),
    }
    for result in results[:max_results]
]
```

Responsibilities:

- fetch `LINKUP_API_KEY` from the environment
- call Linkup’s search API
- retry transient HTTP failures
- normalize provider output into a simpler result shape
- expose the function as an agent tool via `@tool`

One note: this file still contains a fallback `try/except` import for `tool`, unlike `fetch.py`, so the codebase is not fully consistent yet.

### `hexgate/tools/fetch.py`

This implements a Tavily-backed URL extraction tool.

Key snippets:

```python
@tool
@observe(name="tavily_fetch")
@async_retry(retries=3, delay_ms=1000, exceptions=(httpx.HTTPError,))
async def fetch(
    url: str,
    extract_depth: str = "basic",
) -> dict:
```

```python
response = await client.post(
    "https://api.tavily.com/extract",
    headers=headers,
    json=payload,
)
```

```python
return {
    "url": url,
    "title": raw.get("title"),
    "content": content[:20_000],
}
```

Responsibilities:

- fetch `TAVILY_API_KEY`
- call Tavily’s extract endpoint
- retry HTTP failures
- trim returned content to 20,000 characters
- expose the capability as a tool

Together, `websearch.py` and `fetch.py` give the agent a simple two-step research pattern:

1. search the web for candidate sources
2. fetch a specific URL for more detailed extraction

### `hexgate/tracing/__init__.py`

This marks the tracing folder as a package.

### `hexgate/tracing/langfuse.py`

This file isolates Langfuse integration details so the rest of the app does not have to care about SDK differences.

Key snippets:

```python
def observe(*args, **kwargs):
    try:
        from langfuse import observe as langfuse_observe
    except Exception:
        ...
```

```python
init_params = signature(CallbackHandler.__init__).parameters
if "session_id" in init_params:
    return CallbackHandler(
        session_id=session_id,
        user_id=user_id,
        tags=default_tags,
    )
```

```python
handler.langfuse_metadata = {
    "langfuse_session_id": session_id,
    "langfuse_user_id": user_id,
    "langfuse_tags": default_tags,
}
```

```python
config: dict[str, Any] = {"callbacks": [handler]}
if metadata:
    config["metadata"] = {k: v for k, v in metadata.items() if v is not None}
```

Responsibilities:

- provide an `observe` decorator wrapper
- create a Langfuse callback handler
- adapt to old and new Langfuse callback APIs
- build the runnable config passed into LangChain
- resolve the current trace URL when possible

This file is a compatibility boundary. That is useful because vendor SDKs change more often than your own app logic should.

### `hexgate/utils/__init__.py`

This marks the utils folder as a package.

### `hexgate/utils/retry.py`

This provides a lightweight async retry decorator used by the tools.

Key snippet:

```python
def async_retry(retries: int = 3, delay_ms: int = 200, exceptions=(Exception,)):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_err = None
            for attempt in range(retries + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as err:
                    last_err = err
                    if attempt < retries:
                        await asyncio.sleep(delay)
                    else:
                        raise last_err
```

Responsibilities:

- wrap async functions
- retry only selected exception types
- pause between retries
- re-raise the last error after retries are exhausted

This keeps retry logic out of the tool files themselves.

## Architectural Notes

### 1. Separation by concern

The code is split into clear layers:

- `config/` for environment and settings
- `agent/` for assembly and runtime wiring
- `tools/` for external capabilities
- `tracing/` for observability integration
- `utils/` for generic helpers
- `prompts/` for prompt text

That is a good structure for a small agent project because it avoids mixing transport code, prompting, tracing, and app startup in one place.

### 2. Thin entrypoint, fat composition

`demo.py` is intentionally thin. Most interesting logic lives in `factory.py`.

That is a healthy pattern because:

- CLI files stay easy to read
- the same factory can later be reused by tests, APIs, notebooks, or jobs

### 3. Tool-first agent design

The current agent is designed around two explicit tools:

- `web_search`
- `fetch`

That makes the first milestone easy to reason about. The prompt and the code both reflect the same tool inventory.

### 4. Prompt outside Python

Storing the system prompt in `prompts/agent_system.md` is a good call. It keeps prompt editing cheap and prevents long embedded strings from cluttering `factory.py`.

### 5. Version-tolerant Langfuse wrapper

`tracing/langfuse.py` is doing real architectural work, not just boilerplate. It shields the rest of the app from Langfuse SDK changes, which already mattered in this repo.

## Small Gaps / Cleanup Opportunities

- `hexgate/tools/websearch.py` still has the scaffold-style `try/except` import for `tool`, while `fetch.py` now imports it directly.
- `demo.py` uses a hardcoded question; later you may want a CLI arg or interactive prompt.
- There are no tests yet for settings validation, retry behavior, or tool normalization.
- The demo path currently assumes all three provider keys are present, even if a future agent might not always need both tools.

## Short Summary

If I had to describe the structure in one sentence:

`hexgate` is a compact agent runtime where `demo.py` boots the app, `factory.py` assembles the agent, `settings.py` validates config, `websearch.py` and `fetch.py` provide capabilities, `langfuse.py` handles tracing compatibility, and `retry.py` supports resilient tool calls.

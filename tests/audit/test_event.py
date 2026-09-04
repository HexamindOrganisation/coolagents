"""AuditEvent.span_attributes() — the decision span's attribute layout per
``hexgate.tracing.semconv``."""

from __future__ import annotations

import json
from typing import Any

from hexgate.audit import (
    MAX_ARGS_BYTES,
    MAX_VIOLATION_CHARS,
    MAX_VIOLATIONS,
    MAX_ATTRIBUTES_BYTES,
    MAX_HINT_BYTES,
    AuditEvent,
)
from hexgate.runtime import MAX_EVALUATED_ROLES
from hexgate.security.decision import Decision, DecisionOutcome
from hexgate.tracing import semconv


def _decision(**overrides) -> Decision:
    base = dict(
        outcome=DecisionOutcome.DENY, agent_name="example_agent", tool_name="read_file"
    )
    return Decision(**{**base, **overrides})


def _json(wire: dict[str, Any], key: str) -> Any:
    """Decode one of the JSON-string dict attributes."""
    assert isinstance(wire[key], str), key
    return json.loads(wire[key])


def test_span_attributes_happy_path() -> None:
    d = _decision(
        user_roles=("analyst",),
        reason="denied for path",
        error_type="policy_denied",
        hint={"glob": "/x/**"},
        violations=("v1", "v2"),
        arguments={"path": "/etc/passwd"},
        attributes={"department": "finance"},
    )
    ev = AuditEvent(decision=d, user_id="alice", session_id="sess_1")
    wire = ev.span_attributes()

    assert AuditEvent.SCOPE == semconv.SCOPE_AUDIT
    assert wire[semconv.EVENT_ID] == str(ev.event_id)
    assert wire[semconv.AGENT_NAME] == "example_agent"
    assert wire[semconv.TOOL_NAME] == "read_file"
    assert wire[semconv.OUTCOME] == "deny"
    assert wire[semconv.ERROR_TYPE] == "policy_denied"
    assert wire[semconv.REASON] == "denied for path"
    assert wire[semconv.VIOLATIONS] == ["v1", "v2"]
    assert _json(wire, semconv.HINT) == {"glob": "/x/**"}
    assert _json(wire, semconv.ARGUMENTS) == {"path": "/etc/passwd"}
    assert _json(wire, semconv.ATTRIBUTES) == {"department": "finance"}
    assert wire[semconv.USER_ID] == "alice"
    assert wire[semconv.SESSION_ID] == "sess_1"
    # Every key is a semconv name — nothing hand-rolled reaches the wire.
    assert all(k.startswith(("sec_ai.", "gen_ai.")) for k in wire)


def test_span_attributes_omits_occurred_at_and_server_resolved_fields() -> None:
    """occurred_at travels as the span start time, never as an attribute;
    project_id / agent_version_id / received_at are server-resolved."""
    wire = AuditEvent(decision=_decision()).span_attributes()
    assert not any("occurred_at" in k for k in wire)
    assert not any("project_id" in k for k in wire)
    assert not any("agent_version" in k for k in wire)
    assert not any("received_at" in k for k in wire)


def test_span_attributes_none_normalizes_to_empty_string() -> None:
    d = _decision(user_roles=(), error_type=None)
    wire = AuditEvent(decision=d).span_attributes()  # user_id/session_id default ""
    assert wire[semconv.USER_ROLES] == []
    assert wire[semconv.ERROR_TYPE] == ""
    assert wire[semconv.USER_ID] == ""
    assert wire[semconv.SESSION_ID] == ""


def test_span_attributes_carries_the_evaluated_role_set_in_order() -> None:
    """Caller order decides which role is credited with an allow."""
    d = _decision(user_roles=("billing", "support"), deciding_role="billing")
    wire = AuditEvent(decision=d).span_attributes()
    assert wire[semconv.USER_ROLES] == ["billing", "support"]


def test_span_attributes_user_roles_tuple_becomes_a_list() -> None:
    """Decision.user_roles is a tuple; the attribute is a native string array."""
    wire = AuditEvent(decision=_decision(user_roles=("a", "b"))).span_attributes()
    assert wire[semconv.USER_ROLES] == ["a", "b"]
    assert isinstance(wire[semconv.USER_ROLES], list)


def test_span_attributes_deciding_role_need_not_be_the_first_role() -> None:
    """Independent fields: user_roles = who called, deciding_role = who granted."""
    d = _decision(
        outcome=DecisionOutcome.ALLOW,
        user_roles=("billing", "support"),
        deciding_role="support",
    )
    wire = AuditEvent(decision=d).span_attributes()
    assert wire[semconv.USER_ROLES] == ["billing", "support"]
    assert wire[semconv.DECIDING_ROLE] == "support"


def test_span_attributes_deciding_role_empty_on_a_deny() -> None:
    """No role granted the call, so naming one would misdirect the reader."""
    d = _decision(user_roles=("billing", "support"), deciding_role=None)
    wire = AuditEvent(decision=d).span_attributes()
    assert wire[semconv.DECIDING_ROLE] == ""
    assert wire[semconv.USER_ROLES] == ["billing", "support"]


def test_span_attributes_no_roles_sends_an_empty_list() -> None:
    """[''] would be indistinguishable from a role literally named ''."""
    wire = AuditEvent(decision=_decision(user_roles=())).span_attributes()
    assert wire[semconv.USER_ROLES] == []
    assert wire[semconv.DECIDING_ROLE] == ""


def test_span_attributes_does_not_redact_role_names() -> None:
    """Role names are policy identifiers, not caller payloads — the argument
    and attribute redactors must not reach them."""
    d = _decision(user_roles=("token", "api_key"), deciding_role="token")
    wire = AuditEvent(decision=d).span_attributes()
    assert wire[semconv.USER_ROLES] == ["token", "api_key"]
    assert wire[semconv.DECIDING_ROLE] == "token"


def test_span_attributes_violations_tuple_becomes_a_list() -> None:
    wire = AuditEvent(decision=_decision(violations=("a", "b", "c"))).span_attributes()
    assert wire[semconv.VIOLATIONS] == ["a", "b", "c"]
    assert isinstance(wire[semconv.VIOLATIONS], list)


def test_span_attributes_redacts_sensitive_keys_recursively() -> None:
    args = {
        "path": "/x",
        "Password": "hunter2",
        "config": {"api_key": "sk-123", "mode": "safe"},
        "headers": [{"AUTHORIZATION": "Bearer abc"}, {"trace": "t1"}],
    }
    wire = AuditEvent(decision=_decision(arguments=args)).span_attributes()
    assert _json(wire, semconv.ARGUMENTS) == {
        "path": "/x",
        "Password": "[REDACTED]",
        "config": {"api_key": "[REDACTED]", "mode": "safe"},
        "headers": [{"AUTHORIZATION": "[REDACTED]"}, {"trace": "t1"}],
    }


def test_span_attributes_redaction_does_not_mutate_decision_arguments() -> None:
    d = _decision(arguments={"secret": "s3cr3t", "nested": {"token": "t"}})
    AuditEvent(decision=d).span_attributes()
    assert d.arguments == {"secret": "s3cr3t", "nested": {"token": "t"}}


def test_span_attributes_truncates_oversize_arguments_under_platform_cap() -> None:
    big = {"data": "x" * (MAX_ARGS_BYTES * 2)}
    wire = AuditEvent(decision=_decision(arguments=big)).span_attributes()
    args = _json(wire, semconv.ARGUMENTS)
    assert args["_truncated"] is True
    assert args["original_bytes"] > MAX_ARGS_BYTES
    assert args["preview"].startswith('{"data": "xxx')
    # The wire form must fit the platform cap, measured as the platform does:
    # in serialized-JSON bytes — which is exactly what the attribute holds.
    assert len(wire[semconv.ARGUMENTS].encode("utf-8")) <= MAX_ARGS_BYTES


def test_span_attributes_small_arguments_pass_through_untruncated() -> None:
    wire = AuditEvent(decision=_decision(arguments={"path": "/x"})).span_attributes()
    assert _json(wire, semconv.ARGUMENTS) == {"path": "/x"}


def test_span_attributes_when_arguments_are_none_then_the_key_is_absent() -> None:
    """OTel attributes can't carry null: an unset dict field is left out,
    and the enricher defaults it."""
    wire = AuditEvent(decision=_decision(arguments=None)).span_attributes()
    assert semconv.ARGUMENTS not in wire


def test_span_attributes_empty_attributes_is_absent() -> None:
    """An active context with no attributes yields ``{}``; nothing is sent so
    the platform stores '' rather than a meaningless "{}"."""
    wire = AuditEvent(decision=_decision(attributes={})).span_attributes()
    assert semconv.ATTRIBUTES not in wire


def test_span_attributes_absent_attributes_is_absent() -> None:
    wire = AuditEvent(decision=_decision()).span_attributes()
    assert semconv.ATTRIBUTES not in wire
    assert semconv.HINT not in wire


def test_span_attributes_redacts_whole_key_sensitive_attributes() -> None:
    """A bag key named exactly like a secret is a secret someone stuffed in."""
    d = _decision(attributes={"department": "finance", "api_key": "sk-live"})
    wire = AuditEvent(decision=d).span_attributes()
    assert _json(wire, semconv.ATTRIBUTES) == {
        "department": "finance",
        "api_key": "[REDACTED]",
    }


def test_span_attributes_keeps_attribute_keys_that_merely_contain_a_secret_word() -> (
    None
):
    """Attributes are policy facts, so redaction is whole-key only: blanking
    ``authorization_tier`` would leave the ctx-driven deny it caused
    unexplainable, which is what persisting the bag exists to prevent."""
    attrs = {
        "authorization_tier": "restricted",
        "access_token_scope": "read-only",
        "password_rotated_days": 12,
    }
    wire = AuditEvent(decision=_decision(attributes=attrs)).span_attributes()
    assert _json(wire, semconv.ATTRIBUTES) == attrs


def test_span_attributes_argument_redaction_stays_substring_based() -> None:
    """Tool inputs are arbitrary caller data — the looser rule stays for them."""
    wire = AuditEvent(
        decision=_decision(arguments={"auth_token_header": "t"})
    ).span_attributes()
    assert _json(wire, semconv.ARGUMENTS) == {"auth_token_header": "[REDACTED]"}


def test_span_attributes_redaction_does_not_mutate_decision_attributes() -> None:
    d = _decision(attributes={"token": "t0ken", "region": "eu"})
    AuditEvent(decision=d).span_attributes()
    assert d.attributes == {"token": "t0ken", "region": "eu"}


def test_span_attributes_preserves_non_string_attribute_values() -> None:
    """ContextAttributeValue is str | int | bool | list[str]; ``default=str`` in
    the serializer must not stringify the non-str members."""
    attrs = {"clearance_level": 3, "on_call": True, "regions": ["eu", "us"]}
    wire = AuditEvent(decision=_decision(attributes=attrs)).span_attributes()
    assert _json(wire, semconv.ATTRIBUTES) == attrs


def test_span_attributes_truncates_oversize_attributes_under_platform_cap() -> None:
    big = {"blob": "x" * (MAX_ATTRIBUTES_BYTES * 2)}
    wire = AuditEvent(decision=_decision(attributes=big)).span_attributes()
    attrs = _json(wire, semconv.ATTRIBUTES)
    assert attrs["_truncated"] is True
    assert attrs["original_bytes"] > MAX_ATTRIBUTES_BYTES
    assert len(wire[semconv.ATTRIBUTES].encode("utf-8")) <= MAX_ATTRIBUTES_BYTES


def test_span_attributes_attribute_cap_is_independent_of_the_argument_cap() -> None:
    """A bag under MAX_ARGS_BYTES but over MAX_ATTRIBUTES_BYTES still truncates."""
    between = {"blob": "x" * (MAX_ATTRIBUTES_BYTES + 512)}
    assert len(json.dumps(between).encode("utf-8")) < MAX_ARGS_BYTES
    wire = AuditEvent(decision=_decision(attributes=between)).span_attributes()
    assert _json(wire, semconv.ATTRIBUTES)["_truncated"] is True


def test_span_attributes_truncates_oversize_hint_under_platform_cap() -> None:
    """A path-heavy file-scope hint must not be rejected and lose the whole event."""
    big = {"allowed_paths": [f"/srv/data/tenant_{i}/**" for i in range(500)]}
    assert len(json.dumps(big).encode("utf-8")) > MAX_HINT_BYTES
    wire = AuditEvent(decision=_decision(hint=big)).span_attributes()
    hint = _json(wire, semconv.HINT)
    assert hint["_truncated"] is True
    assert hint["original_bytes"] > MAX_HINT_BYTES
    assert len(wire[semconv.HINT].encode("utf-8")) <= MAX_HINT_BYTES


def test_span_attributes_hint_truncation_does_not_touch_the_decision() -> None:
    """Only the audit copy is trimmed — as_error_payload keeps the full hint."""
    big = {"allowed_paths": [f"/srv/data/tenant_{i}/**" for i in range(500)]}
    d = _decision(hint=big)
    AuditEvent(decision=d).span_attributes()
    assert d.hint == big
    assert d.as_error_payload()["hint"] == big


def test_span_attributes_small_hint_passes_through_untruncated() -> None:
    wire = AuditEvent(decision=_decision(hint={"glob": "/x/**"})).span_attributes()
    assert _json(wire, semconv.HINT) == {"glob": "/x/**"}


def test_event_id_unique_per_event() -> None:
    w1 = AuditEvent(decision=_decision()).span_attributes()
    w2 = AuditEvent(decision=_decision()).span_attributes()
    assert w1[semconv.EVENT_ID] != w2[semconv.EVENT_ID]


def test_occurred_at_defaults_to_an_aware_utc_datetime() -> None:
    """The sender turns it into span start time; a naive datetime would be
    read in local time and land the event hours off."""
    ev = AuditEvent(decision=_decision())
    assert ev.occurred_at.utcoffset() is not None
    assert ev.occurred_at.utcoffset().total_seconds() == 0


def test_span_attributes_caps_violations_at_the_platform_list_limit() -> None:
    """A multi-role deny unions violations across roles; over the platform's
    64-item cap the event would be rejected and a *denied* call go unrecorded."""
    d = _decision(violations=tuple(f"args.f{i} == 1" for i in range(72)))

    wire = AuditEvent(decision=d).span_attributes()

    assert len(wire[semconv.VIOLATIONS]) == MAX_VIOLATIONS
    assert wire[semconv.VIOLATIONS][-1] == "(+9 more)"  # 63 kept + marker
    assert wire[semconv.VIOLATIONS][0] == "args.f0 == 1"


def test_span_attributes_keeps_violations_under_the_cap_intact() -> None:
    d = _decision(violations=tuple(f"args.f{i} == 1" for i in range(MAX_VIOLATIONS)))

    wire = AuditEvent(decision=d).span_attributes()

    assert len(wire[semconv.VIOLATIONS]) == MAX_VIOLATIONS
    assert "more)" not in wire[semconv.VIOLATIONS][-1]


def test_span_attributes_truncates_an_overlong_violation_visibly() -> None:
    """Per-item cap too: the platform bounds each string at 1024 chars."""
    d = _decision(violations=("x" * 2000,))

    violation = AuditEvent(decision=d).span_attributes()[semconv.VIOLATIONS][0]

    assert len(violation) == MAX_VIOLATION_CHARS
    assert violation.endswith("...")


def test_capped_violations_survive_the_platform_schema() -> None:
    """The point of the cap: the trimmed list is one the platform accepts."""
    d = _decision(violations=tuple(f"args.f{i} == 1" for i in range(200)))

    violations = AuditEvent(decision=d).span_attributes()[semconv.VIOLATIONS]

    assert len(violations) <= MAX_VIOLATIONS
    assert all(len(v) <= MAX_VIOLATION_CHARS for v in violations)


def test_decision_keeps_every_violation_for_the_host() -> None:
    """Only the audit copy is trimmed — the model-facing payload is untouched."""
    d = _decision(violations=tuple(f"args.f{i} == 1" for i in range(72)))

    AuditEvent(decision=d).span_attributes()

    assert len(d.violations) == 72
    assert len(d.as_error_payload()["violations"]) == 72


def test_a_full_role_set_goes_out_whole() -> None:
    """No cap of its own: the enforcer already bounds the set at
    MAX_EVALUATED_ROLES. That it stays <= the platform's list cap is asserted
    platform-side; here, only that a full set reaches the wire intact.
    """
    roles = tuple(f"role_{i}" for i in range(MAX_EVALUATED_ROLES))
    d = _decision(user_roles=roles, deciding_role=roles[-1])

    wire = AuditEvent(decision=d).span_attributes()

    assert wire[semconv.USER_ROLES] == list(roles)
    assert wire[semconv.DECIDING_ROLE] == roles[-1]

"""AuditEvent.as_payload() field mapping for the platform's audit endpoint."""

from __future__ import annotations

import json

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


def _decision(**overrides) -> Decision:
    base = dict(
        outcome=DecisionOutcome.DENY, agent_name="example_agent", tool_name="read_file"
    )
    return Decision(**{**base, **overrides})


def test_as_payload_full_payload() -> None:
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
    wire = ev.as_payload()

    assert wire["event_id"] == str(ev.event_id)
    assert wire["occurred_at"] == ev.occurred_at.isoformat()
    assert wire["agent_name"] == "example_agent"
    assert wire["tool_name"] == "read_file"
    assert wire["outcome"] == "deny"
    assert "role" not in wire  # legacy scalar dropped from the wire
    assert wire["error_type"] == "policy_denied"
    assert wire["reason"] == "denied for path"
    assert wire["violations"] == ["v1", "v2"]
    assert wire["hint"] == {"glob": "/x/**"}
    assert wire["arguments"] == {"path": "/etc/passwd"}
    assert wire["attributes"] == {"department": "finance"}
    assert wire["user_id"] == "alice"
    assert wire["session_id"] == "sess_1"


def test_as_payload_server_resolved_fields_absent() -> None:
    """project_id, agent_version_id, received_at are server-resolved or server-stamped."""
    wire = AuditEvent(decision=_decision()).as_payload()
    assert "project_id" not in wire
    assert "agent_version_id" not in wire
    assert "received_at" not in wire


def test_as_payload_none_normalizes_to_empty_string() -> None:
    d = _decision(user_roles=(), error_type=None)
    wire = AuditEvent(decision=d).as_payload()  # user_id/session_id default to ""
    assert wire["user_roles"] == []
    assert wire["error_type"] == ""
    assert wire["user_id"] == ""
    assert wire["session_id"] == ""


def test_as_payload_carries_the_evaluated_role_set_in_order() -> None:
    """Caller order decides which role is credited with an allow."""
    d = _decision(user_roles=("billing", "support"), deciding_role="billing")
    wire = AuditEvent(decision=d).as_payload()
    assert wire["user_roles"] == ["billing", "support"]


def test_as_payload_user_roles_tuple_serializes_as_list() -> None:
    """Decision.user_roles is a tuple; JSON needs a list."""
    wire = AuditEvent(decision=_decision(user_roles=("a", "b"))).as_payload()
    assert wire["user_roles"] == ["a", "b"]
    assert isinstance(wire["user_roles"], list)


def test_as_payload_deciding_role_need_not_be_the_first_role() -> None:
    """Independent fields: role = who called, deciding_role = who granted."""
    d = _decision(
        outcome=DecisionOutcome.ALLOW,
        user_roles=("billing", "support"),
        deciding_role="support",
    )
    wire = AuditEvent(decision=d).as_payload()
    assert wire["user_roles"] == ["billing", "support"]
    assert wire["deciding_role"] == "support"


def test_as_payload_deciding_role_empty_on_a_deny() -> None:
    """No role granted the call, so naming one would misdirect the reader."""
    d = _decision(user_roles=("billing", "support"), deciding_role=None)
    wire = AuditEvent(decision=d).as_payload()
    assert wire["deciding_role"] == ""
    assert wire["user_roles"] == ["billing", "support"]


def test_as_payload_no_roles_sends_an_empty_list() -> None:
    """[''] would be indistinguishable from a role literally named ''."""
    wire = AuditEvent(decision=_decision(user_roles=())).as_payload()
    assert wire["user_roles"] == []
    assert wire["deciding_role"] == ""


def test_as_payload_does_not_redact_role_names() -> None:
    """Role names are policy identifiers, not caller payloads — the argument
    and attribute redactors must not reach them."""
    d = _decision(user_roles=("token", "api_key"), deciding_role="token")
    wire = AuditEvent(decision=d).as_payload()
    assert wire["user_roles"] == ["token", "api_key"]
    assert wire["deciding_role"] == "token"


def test_as_payload_violations_tuple_serializes_as_list() -> None:
    """Decision.violations is tuple[str, ...] but the wire payload is a list."""
    wire = AuditEvent(decision=_decision(violations=("a", "b", "c"))).as_payload()
    assert wire["violations"] == ["a", "b", "c"]
    assert isinstance(wire["violations"], list)


def test_as_payload_redacts_sensitive_keys_recursively() -> None:
    args = {
        "path": "/x",
        "Password": "hunter2",
        "config": {"api_key": "sk-123", "mode": "safe"},
        "headers": [{"AUTHORIZATION": "Bearer abc"}, {"trace": "t1"}],
    }
    wire = AuditEvent(decision=_decision(arguments=args)).as_payload()
    assert wire["arguments"] == {
        "path": "/x",
        "Password": "[REDACTED]",
        "config": {"api_key": "[REDACTED]", "mode": "safe"},
        "headers": [{"AUTHORIZATION": "[REDACTED]"}, {"trace": "t1"}],
    }


def test_as_payload_redaction_does_not_mutate_decision_arguments() -> None:
    d = _decision(arguments={"secret": "s3cr3t", "nested": {"token": "t"}})
    AuditEvent(decision=d).as_payload()
    assert d.arguments == {"secret": "s3cr3t", "nested": {"token": "t"}}


def test_as_payload_truncates_oversize_arguments_under_platform_cap() -> None:
    big = {"data": "x" * (MAX_ARGS_BYTES * 2)}
    wire = AuditEvent(decision=_decision(arguments=big)).as_payload()
    args = wire["arguments"]
    assert args["_truncated"] is True
    assert args["original_bytes"] > MAX_ARGS_BYTES
    assert args["preview"].startswith('{"data": "xxx')
    # The wire form must fit the platform cap, measured as the platform does.
    assert len(json.dumps(args, default=str).encode("utf-8")) <= MAX_ARGS_BYTES


def test_as_payload_small_arguments_pass_through_untruncated() -> None:
    wire = AuditEvent(decision=_decision(arguments={"path": "/x"})).as_payload()
    assert wire["arguments"] == {"path": "/x"}


def test_as_payload_empty_attributes_normalizes_to_none() -> None:
    """An active context with no attributes yields ``{}``; the wire says None so
    the platform stores '' rather than a meaningless "{}"."""
    wire = AuditEvent(decision=_decision(attributes={})).as_payload()
    assert wire["attributes"] is None


def test_as_payload_absent_attributes_is_none() -> None:
    wire = AuditEvent(decision=_decision()).as_payload()
    assert wire["attributes"] is None


def test_as_payload_redacts_whole_key_sensitive_attributes() -> None:
    """A bag key named exactly like a secret is a secret someone stuffed in."""
    d = _decision(attributes={"department": "finance", "api_key": "sk-live"})
    wire = AuditEvent(decision=d).as_payload()
    assert wire["attributes"] == {
        "department": "finance",
        "api_key": "[REDACTED]",
    }


def test_as_payload_keeps_attribute_keys_that_merely_contain_a_secret_word() -> None:
    """Attributes are policy facts, so redaction is whole-key only: blanking
    ``authorization_tier`` would leave the ctx-driven deny it caused
    unexplainable, which is what persisting the bag exists to prevent."""
    attrs = {
        "authorization_tier": "restricted",
        "access_token_scope": "read-only",
        "password_rotated_days": 12,
    }
    wire = AuditEvent(decision=_decision(attributes=attrs)).as_payload()
    assert wire["attributes"] == attrs


def test_as_payload_argument_redaction_stays_substring_based() -> None:
    """Tool inputs are arbitrary caller data — the looser rule stays for them."""
    wire = AuditEvent(
        decision=_decision(arguments={"auth_token_header": "t"})
    ).as_payload()
    assert wire["arguments"] == {"auth_token_header": "[REDACTED]"}


def test_as_payload_redaction_does_not_mutate_decision_attributes() -> None:
    d = _decision(attributes={"token": "t0ken", "region": "eu"})
    AuditEvent(decision=d).as_payload()
    assert d.attributes == {"token": "t0ken", "region": "eu"}


def test_as_payload_preserves_non_string_attribute_values() -> None:
    """ContextAttributeValue is str | int | bool | list[str]; ``default=str`` in
    the serializer must not stringify the non-str members."""
    attrs = {"clearance_level": 3, "on_call": True, "regions": ["eu", "us"]}
    wire = AuditEvent(decision=_decision(attributes=attrs)).as_payload()
    assert wire["attributes"] == attrs


def test_as_payload_truncates_oversize_attributes_under_platform_cap() -> None:
    big = {"blob": "x" * (MAX_ATTRIBUTES_BYTES * 2)}
    wire = AuditEvent(decision=_decision(attributes=big)).as_payload()
    attrs = wire["attributes"]
    assert attrs["_truncated"] is True
    assert attrs["original_bytes"] > MAX_ATTRIBUTES_BYTES
    # The wire form must fit the platform cap, measured as the platform does.
    assert len(json.dumps(attrs, default=str).encode("utf-8")) <= MAX_ATTRIBUTES_BYTES


def test_as_payload_attribute_cap_is_independent_of_the_argument_cap() -> None:
    """A bag under MAX_ARGS_BYTES but over MAX_ATTRIBUTES_BYTES still truncates."""
    between = {"blob": "x" * (MAX_ATTRIBUTES_BYTES + 512)}
    assert len(json.dumps(between).encode("utf-8")) < MAX_ARGS_BYTES
    wire = AuditEvent(decision=_decision(attributes=between)).as_payload()
    assert wire["attributes"]["_truncated"] is True


def test_as_payload_truncates_oversize_hint_under_platform_cap() -> None:
    """A path-heavy file-scope hint must not 413 and lose the whole event."""
    big = {"allowed_paths": [f"/srv/data/tenant_{i}/**" for i in range(500)]}
    assert len(json.dumps(big).encode("utf-8")) > MAX_HINT_BYTES
    wire = AuditEvent(decision=_decision(hint=big)).as_payload()
    hint = wire["hint"]
    assert hint["_truncated"] is True
    assert hint["original_bytes"] > MAX_HINT_BYTES
    # The wire form must fit the platform cap, measured as the platform does.
    assert len(json.dumps(hint, default=str).encode("utf-8")) <= MAX_HINT_BYTES


def test_as_payload_hint_truncation_does_not_touch_the_decision() -> None:
    """Only the audit copy is trimmed — as_error_payload keeps the full hint."""
    big = {"allowed_paths": [f"/srv/data/tenant_{i}/**" for i in range(500)]}
    d = _decision(hint=big)
    AuditEvent(decision=d).as_payload()
    assert d.hint == big
    assert d.as_error_payload()["hint"] == big


def test_as_payload_small_hint_passes_through_untruncated() -> None:
    wire = AuditEvent(decision=_decision(hint={"glob": "/x/**"})).as_payload()
    assert wire["hint"] == {"glob": "/x/**"}


def test_as_payload_under_cap_payloads_do_not_alias_the_decision() -> None:
    """Every wire payload is a copy: mutating one must not reach the live
    ``Decision`` the host holds, whose ``hint`` also goes to the model via
    ``as_error_payload``."""
    d = _decision(
        hint={"glob": "/x/**"},
        arguments={"path": "/x"},
        attributes={"department": "finance"},
    )
    wire = AuditEvent(decision=d).as_payload()

    for key, source in (
        ("hint", d.hint),
        ("arguments", d.arguments),
        ("attributes", d.attributes),
    ):
        assert wire[key] is not source, key
        wire[key]["injected"] = True
        assert "injected" not in source, key


def test_event_id_and_occurred_at_unique_per_event() -> None:
    w1 = AuditEvent(decision=_decision()).as_payload()
    w2 = AuditEvent(decision=_decision()).as_payload()
    assert w1["event_id"] != w2["event_id"]
    assert "+00:00" in w1["occurred_at"]


def test_as_payload_caps_violations_at_the_platform_list_limit() -> None:
    """A multi-role deny unions violations across roles; over the platform's
    64-item cap the event is rejected (422) and a *denied* call goes unrecorded."""
    d = _decision(violations=tuple(f"args.f{i} == 1" for i in range(72)))

    wire = AuditEvent(decision=d).as_payload()

    assert len(wire["violations"]) == MAX_VIOLATIONS
    assert wire["violations"][-1] == "(+9 more)"  # 63 kept + marker
    assert wire["violations"][0] == "args.f0 == 1"


def test_as_payload_keeps_violations_under_the_cap_intact() -> None:
    d = _decision(violations=tuple(f"args.f{i} == 1" for i in range(MAX_VIOLATIONS)))

    wire = AuditEvent(decision=d).as_payload()

    assert len(wire["violations"]) == MAX_VIOLATIONS
    assert "more)" not in wire["violations"][-1]


def test_as_payload_truncates_an_overlong_violation_visibly() -> None:
    """Per-item cap too: the platform bounds each string at 1024 chars."""
    d = _decision(violations=("x" * 2000,))

    violation = AuditEvent(decision=d).as_payload()["violations"][0]

    assert len(violation) == MAX_VIOLATION_CHARS
    assert violation.endswith("...")


def test_capped_violations_survive_the_platform_schema() -> None:
    """The point of the cap: the trimmed payload is one the platform accepts."""
    d = _decision(violations=tuple(f"args.f{i} == 1" for i in range(200)))

    violations = AuditEvent(decision=d).as_payload()["violations"]

    assert len(violations) <= MAX_VIOLATIONS
    assert all(len(v) <= MAX_VIOLATION_CHARS for v in violations)


def test_decision_keeps_every_violation_for_the_host() -> None:
    """Only the audit copy is trimmed — the model-facing payload is untouched."""
    d = _decision(violations=tuple(f"args.f{i} == 1" for i in range(72)))

    AuditEvent(decision=d).as_payload()

    assert len(d.violations) == 72
    assert len(d.as_error_payload()["violations"]) == 72


def test_a_full_role_set_goes_out_whole() -> None:
    """No cap of its own: the enforcer already bounds the set at
    MAX_EVALUATED_ROLES. That it stays <= the platform's list cap is asserted
    platform-side; here, only that a full set reaches the wire intact.
    """
    roles = tuple(f"role_{i}" for i in range(MAX_EVALUATED_ROLES))
    d = _decision(user_roles=roles, deciding_role=roles[-1])

    wire = AuditEvent(decision=d).as_payload()

    assert wire["user_roles"] == list(roles)
    assert wire["deciding_role"] == roles[-1]

"""Cross-domain constants: the triple-default seed identity + role names.

Kept in one place so every domain service (and the test suite) references the
same fixed UUIDs and role strings instead of redefining them.
"""

from hexgate_api.seeds import DEFAULT_AGENT_NAME

# Triple-default seed identity (M3). Fixed UUIDs so every fresh dev DB
# produces identical rows — tests and integration scripts can reference
# these constants directly instead of looking up by name.
#
# Production (hosted Hexgate) sets HEXGATE_SEED=skip to start with a
# truly empty DB. Self-hosters and `make platform-api` get a working
# install on first boot without any setup.
DEFAULT_ORG_ID = "00000000-0000-0000-0000-000000000001"
DEFAULT_ORG_SLUG = "default"
DEFAULT_ORG_NAME = "Default Organization"

DEFAULT_USER_ID = "00000000-0000-0000-0000-000000000002"
# ``.local`` is a reserved TLD per RFC 6762 — pydantic's EmailStr (used in
# fastapi-users' UserRead schema) rejects it, so /users/me crashes when the
# admin's email goes through serialization. Use ``.dev`` (a real TLD Google
# owns) so the email is syntactically valid while still clearly identifying
# this as the default-seed admin, not a real mailbox.
DEFAULT_USER_EMAIL = "admin@hexgate.dev"

DEFAULT_PROJECT_ID = "00000000-0000-0000-0000-000000000003"
DEFAULT_PROJECT_NAME = "support-bot"

DEFAULT_MEMBERSHIP_ID = "00000000-0000-0000-0000-000000000004"

PROTECTED_AGENT_NAMES = {DEFAULT_AGENT_NAME}

# Role constants — strings (not Enum) so we can add billing_admin etc.
# without a schema change. Validation happens at the API layer where
# clients send the value as a request body field.
ROLE_OWNER = "owner"
ROLE_ADMIN = "admin"
ROLE_MEMBER = "member"
ALL_ROLES = {ROLE_OWNER, ROLE_ADMIN, ROLE_MEMBER}

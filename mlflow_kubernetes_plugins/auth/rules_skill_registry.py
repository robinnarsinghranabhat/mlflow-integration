"""Skill Registry (RFC-0008) authorization deltas, gated on the router module being present.

Verb conventions follow ``apply_mcp_registry_deltas``: collection POST is ``create``, search is
``list`` with a response filter, reads are ``get``, every nested mutation (including nested
DELETE) is ``update``, and only deleting the Skill itself is ``delete``.
"""

from __future__ import annotations

from mlflow_kubernetes_plugins.auth.collection_filters import COLLECTION_POLICY_RESPONSE_SKILLS
from mlflow_kubernetes_plugins.auth.resource_names import RESOURCE_NAME_PARSER_SKILL_NAME
from mlflow_kubernetes_plugins.auth.rules import AuthorizationRule, _skills_rule

_SKILL_ROUTE_PREFIXES = ("/ajax-api/3.0/mlflow/skills", "/api/3.0/mlflow/skills")


def _named_skill_rules(
    base: str,
) -> dict[tuple[str, str], AuthorizationRule | tuple[AuthorizationRule, ...]]:
    def named(verb: str) -> AuthorizationRule:
        return _skills_rule(verb, resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,))

    return {
        (f"{base}/versions", "GET"): named("get"),
        (f"{base}/versions", "POST"): named("update"),
        (f"{base}/versions/<version>", "GET"): named("get"),
        (f"{base}/versions/<version>", "PATCH"): named("update"),
        (f"{base}/versions/<version>", "DELETE"): named("update"),
        (f"{base}/versions/<version>/tags", "POST"): named("update"),
        (f"{base}/versions/<version>/tags/<path:key>", "DELETE"): named("update"),
        (f"{base}/tags", "POST"): named("update"),
        (f"{base}/tags/<path:key>", "DELETE"): named("update"),
        (f"{base}/aliases", "POST"): named("update"),
        (f"{base}/aliases/<alias>", "GET"): named("get"),
        (f"{base}/aliases/<alias>", "DELETE"): named("update"),
        # Keep the catch-all Skill routes last so nested regexes win first.
        (base, "GET"): named("get"),
        (base, "PATCH"): named("update"),
        (base, "DELETE"): named("delete"),
    }


def apply_skill_registry_deltas(
    *,
    path_authorization_rules: dict[
        tuple[str, str], AuthorizationRule | tuple[AuthorizationRule, ...]
    ],
) -> None:
    for prefix in _SKILL_ROUTE_PREFIXES:
        path_authorization_rules.update(
            {
                (prefix, "POST"): _skills_rule("create"),
                (prefix, "GET"): _skills_rule(
                    "list",
                    collection_policy=COLLECTION_POLICY_RESPONSE_SKILLS,
                ),
                # Register and bulk-register upsert the parent Skill and add versions. Like MCP
                # upserts they need update, checked workspace-wide because the Skill names
                # are in the (possibly multipart) body.
                (f"{prefix}/register", "POST"): _skills_rule("update"),
                (f"{prefix}/bulk-register", "POST"): _skills_rule("update"),
            }
        )
        # Register organization-scoped routes first: the regex matcher takes the first match,
        # and FastAPI resolves "/@org/name" to the organization form before "/{name}/...".
        path_authorization_rules.update(_named_skill_rules(f"{prefix}/@<organization>/<name>"))
        path_authorization_rules.update(_named_skill_rules(f"{prefix}/<name>"))

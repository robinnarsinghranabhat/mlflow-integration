from unittest.mock import Mock

import pytest
from mlflow_kubernetes_plugins.auth._compat import HAS_SKILL_REGISTRY
from mlflow_kubernetes_plugins.auth.collection_filters import (
    COLLECTION_POLICY_RESPONSE_SKILLS,
    apply_response_collection_filters,
)
from mlflow_kubernetes_plugins.auth.compiler import (
    _extract_path_params,
    _find_authorization_rules,
)
from mlflow_kubernetes_plugins.auth.constants import RESOURCE_SKILLS
from mlflow_kubernetes_plugins.auth.core import _RequestIdentity
from mlflow_kubernetes_plugins.auth.request_context import AuthorizationRequest
from mlflow_kubernetes_plugins.auth.resource_names import (
    RESOURCE_NAME_PARSER_SKILL_NAME,
    ResourceNameResolutionError,
    resolve_resource_names,
)
from mlflow_kubernetes_plugins.auth.rules import AuthorizationRule

requires_skill_registry = pytest.mark.skipif(
    not HAS_SKILL_REGISTRY,
    reason="Installed MLflow version does not expose the Skill Registry routes.",
)


@pytest.fixture(autouse=True)
def _compile_rules(compile_auth_rules):
    compile_auth_rules([])


def _request(path: str, method: str, path_params: dict[str, str]) -> AuthorizationRequest:
    return AuthorizationRequest(
        authorization_header=None,
        forwarded_access_token=None,
        remote_user_header_value=None,
        remote_groups_header_value=None,
        path=path,
        method=method,
        workspace="team-a",
        path_params=path_params,
    )


@requires_skill_registry
@pytest.mark.parametrize("prefix", ["/api/3.0/mlflow/skills", "/ajax-api/3.0/mlflow/skills"])
@pytest.mark.parametrize(
    ("method", "suffix", "expected_verb", "expected_names", "expected_policy"),
    [
        ("POST", "", "create", (), None),
        ("GET", "", "list", (), COLLECTION_POLICY_RESPONSE_SKILLS),
        ("POST", "/register", "update", (), None),
        ("POST", "/bulk-register", "update", (), None),
        ("GET", "/pdf", "get", ("pdf",), None),
        ("GET", "/@acme/pdf", "get", ("@acme/pdf",), None),
        ("PATCH", "/@acme/pdf", "update", ("@acme/pdf",), None),
        ("DELETE", "/pdf", "delete", ("pdf",), None),
        ("DELETE", "/@acme/pdf", "delete", ("@acme/pdf",), None),
        ("GET", "/@acme/pdf/versions", "get", ("@acme/pdf",), None),
        ("POST", "/pdf/versions", "update", ("pdf",), None),
        ("PATCH", "/@acme/pdf/versions/3", "update", ("@acme/pdf",), None),
        ("DELETE", "/pdf/versions/3", "update", ("pdf",), None),
        ("DELETE", "/@acme/pdf/versions/3/tags/team/a", "update", ("@acme/pdf",), None),
        ("DELETE", "/pdf/tags/team/a", "update", ("pdf",), None),
        ("POST", "/@acme/pdf/aliases", "update", ("@acme/pdf",), None),
        ("GET", "/pdf/aliases/stable", "get", ("pdf",), None),
        ("DELETE", "/@acme/pdf/aliases/stable", "update", ("@acme/pdf",), None),
        # FastAPI resolves this to organization "acme" and Skill "versions", not to the
        # versions of a Skill named "@acme"; the authorization rule must agree.
        ("GET", "/@acme/versions", "get", ("@acme/versions",), None),
    ],
)
def test_skill_routes_resolve_to_skills_rules(
    prefix, method, suffix, expected_verb, expected_names, expected_policy
):
    path = f"{prefix}{suffix}"

    rules = _find_authorization_rules(path, method)

    assert rules is not None
    assert len(rules) == 1
    rule = rules[0]
    assert (rule.verb, rule.resource) == (expected_verb, RESOURCE_SKILLS)
    assert rule.collection_policy == expected_policy
    if expected_names:
        request = _request(path, method, _extract_path_params(path, method))
        assert resolve_resource_names(request, list(rule.resource_name_parsers)) == expected_names
    else:
        assert rule.resource_name_parsers == ()


@pytest.mark.parametrize(
    ("path_params", "expected"),
    [
        ({"name": "pdf"}, ("pdf",)),
        ({"name": "pdf", "organization": "acme"}, ("@acme/pdf",)),
        ({"name": "pdf", "organization": ""}, ("pdf",)),
    ],
)
def test_skill_name_parser_formats_organization(path_params, expected):
    request = _request("/api/3.0/mlflow/skills/x", "GET", path_params)

    assert resolve_resource_names(request, [RESOURCE_NAME_PARSER_SKILL_NAME]) == expected


def test_skill_name_parser_requires_name():
    request = _request("/api/3.0/mlflow/skills/x", "GET", {"organization": "acme"})

    with pytest.raises(ResourceNameResolutionError, match="name"):
        resolve_resource_names(request, [RESOURCE_NAME_PARSER_SKILL_NAME])


def test_apply_response_collection_filters_filters_skills():
    authorizer = Mock()
    authorizer.is_allowed.side_effect = lambda *args, **kwargs: (
        kwargs.get("resource_name")
        in {
            "visible",
            "@acme/visible",
        }
    )

    filtered, enforceable = apply_response_collection_filters(
        {
            "skills": [
                {"name": "visible", "organization": ""},
                {"name": "visible", "organization": "acme"},
                {"name": "hidden", "organization": "acme"},
                {"name": "hidden"},
            ],
            "next_page_token": "tok",
        },
        [
            AuthorizationRule(
                "list",
                resource=RESOURCE_SKILLS,
                collection_policy=COLLECTION_POLICY_RESPONSE_SKILLS,
            )
        ],
        authorizer=authorizer,
        identity=_RequestIdentity(token="token"),
        workspace_name="team-a",
    )

    assert enforceable is True
    assert filtered == {
        "skills": [
            {"name": "visible", "organization": ""},
            {"name": "visible", "organization": "acme"},
        ],
        "next_page_token": "tok",
    }

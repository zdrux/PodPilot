from types import SimpleNamespace

import pytest
from kubernetes.dynamic.resource import ResourceList

from podpilot_openshift.discovery import (
    ResourceCatalog,
    ResourceCatalogError,
    ResourceDescriptor,
    resource_is_safe,
)


def resource(
    name: str,
    api_version: str,
    kind: str,
    *,
    namespaced: bool = True,
    verbs=("get", "list"),
    singular_name: str = "",
    short_names=(),
):
    return SimpleNamespace(
        name=name,
        group_version=api_version,
        kind=kind,
        namespaced=namespaced,
        verbs=verbs,
        singular_name=singular_name,
        short_names=short_names,
    )


def test_catalog_discovers_aliases_and_prefers_core_resource_on_collision() -> None:
    calls = []

    def search(**kwargs):
        calls.append(kwargs)
        return [
            resource("events", "v1", "Event", singular_name="event", short_names=("ev",)),
            resource("events", "events.k8s.io/v1", "Event"),
            resource("routes", "route.openshift.io/v1", "Route", singular_name="route"),
        ]

    catalog = ResourceCatalog(search, ttl_seconds=300)

    assert catalog.resolve("ev", verb="list").api_version == "v1"
    assert catalog.resolve("events", verb="list").api_version == "v1"
    assert catalog.resolve("routes.route.openshift.io", verb="get").kind == "Route"
    assert calls == [{}]
    catalog.entries()
    assert calls == [{}]


def test_catalog_filters_sensitive_identity_and_subresources() -> None:
    catalog = ResourceCatalog(lambda **_kwargs: [
        resource("pods", "v1", "Pod"),
        resource("pods/log", "v1", "Pod"),
        resource("secrets", "v1", "Secret"),
        resource("users", "user.openshift.io/v1", "User", namespaced=False),
        resource("tokenreviews", "authentication.k8s.io/v1", "TokenReview", namespaced=False),
    ])

    assert [item.name for item in catalog.entries()] == ["pods"]
    with pytest.raises(ResourceCatalogError, match="outside the read policy"):
        catalog.resolve("secrets", verb="get")


def test_catalog_requires_requested_read_verb() -> None:
    catalog = ResourceCatalog(lambda **_kwargs: [
        resource("widgets", "example.io/v1", "Widget", verbs=("list",)),
    ])

    assert catalog.resolve("widgets", verb="list").kind == "Widget"
    with pytest.raises(ResourceCatalogError, match="unavailable"):
        catalog.resolve("widgets", verb="get")


def test_catalog_accepts_watch_only_resources_and_exposes_available_verbs() -> None:
    catalog = ResourceCatalog(lambda **_kwargs: [
        resource("authconfigs", "authorino.kuadrant.io/v1beta3", "AuthConfig", verbs=("watch",)),
    ])

    prompt = catalog.prompt_entries(query="Authorino policy", limit=5)

    assert prompt == [{
        "resource": "authconfigs",
        "apiVersion": "authorino.kuadrant.io/v1beta3",
        "kind": "AuthConfig",
        "namespaced": True,
        "verbs": ["watch"],
    }]


def test_catalog_prefers_stable_version_and_qualifies_cross_group_collisions() -> None:
    catalog = ResourceCatalog(lambda **_kwargs: [
        resource("widgets", "example.io/v1beta2", "Widget"),
        resource("widgets", "example.io/v1", "Widget"),
        resource("events", "v1", "Event"),
        resource("events", "events.k8s.io/v1", "Event"),
    ])

    assert catalog.resolve("widgets", verb="list").api_version == "example.io/v1"
    prompt = catalog.prompt_entries(query="show events", limit=10)
    event_names = {entry["resource"] for entry in prompt if entry["kind"] == "Event"}
    assert event_names == {"events.core", "events.events.k8s.io"}


def test_catalog_uses_exact_coordinates_to_disambiguate_same_plural() -> None:
    catalog = ResourceCatalog(lambda **_kwargs: [
        resource("routes", "route.openshift.io/v1", "Route"),
        resource("routes", "serving.knative.dev/v1", "Route"),
    ])

    selected = catalog.resolve(
        "routes", verb="list", api_version="route.openshift.io/v1", kind="Route"
    )

    assert selected.api_version == "route.openshift.io/v1"
    with pytest.raises(ResourceCatalogError, match="coordinates do not match"):
        catalog.resolve("routes.route.openshift.io", verb="list", api_version="v1", kind="Pod")


def test_prompt_catalog_ranks_question_match_before_alphabetical_limit() -> None:
    catalog = ResourceCatalog(lambda **_kwargs: [
        resource(f"aaa{index}", "example.io/v1", f"Aaa{index}") for index in range(10)
    ] + [resource("zebras", "example.io/v1", "Zebra")])

    prompt = catalog.prompt_entries(query="which zebras are available?", limit=2)

    assert prompt[0]["resource"] == "zebras"


def test_prompt_catalog_matches_operator_domain_term_without_full_kind_name() -> None:
    catalog = ResourceCatalog(lambda **_kwargs: [
        resource("deployments", "apps/v1", "Deployment"),
        resource(
            "ingresscontrollers", "operator.openshift.io/v1", "IngressController",
            namespaced=True,
        ),
    ])

    prompt = catalog.prompt_entries(query="what are the cluster ingress IPs?", limit=1)

    assert prompt[0]["kind"] == "IngressController"


def test_catalog_skips_lazy_resource_list_without_resolving_its_base_resource() -> None:
    class FailingResources:
        def get(self, **_kwargs):
            raise RuntimeError("Template base resource is not available")

    lazy_template_list = ResourceList(
        client=SimpleNamespace(resources=FailingResources()),
        group="template.openshift.io",
        api_version="v1",
        base_kind="Template",
        base_resource_lookup={
            "group": "template.openshift.io", "api_version": "v1", "kind": "Template",
        },
    )
    catalog = ResourceCatalog(lambda **_kwargs: [
        lazy_template_list,
        resource("pods", "v1", "Pod"),
    ])

    assert [entry.name for entry in catalog.entries()] == ["pods"]


def test_catalog_invalidation_forces_fresh_discovery() -> None:
    calls = 0

    def search(**_kwargs):
        nonlocal calls
        calls += 1
        kind = "Pod" if calls == 1 else "Kafka"
        name = "pods" if calls == 1 else "kafkas"
        api_version = "v1" if calls == 1 else "kafka.strimzi.io/v1beta2"
        return [resource(name, api_version, kind)]

    catalog = ResourceCatalog(search)

    assert [entry.kind for entry in catalog.entries()] == ["Pod"]
    assert [entry.kind for entry in catalog.entries()] == ["Pod"]
    catalog.invalidate()
    assert [entry.kind for entry in catalog.entries()] == ["Kafka"]
    assert calls == 2


def test_policy_denies_sensitive_descriptor_even_when_get_is_advertised() -> None:
    descriptor = ResourceDescriptor(
        name="oauthaccesstokens",
        api_version="oauth.openshift.io/v1",
        kind="OAuthAccessToken",
        namespaced=False,
        verbs=("get", "list"),
    )

    assert resource_is_safe(descriptor) is False

from types import SimpleNamespace

import pytest

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


def test_prompt_catalog_ranks_question_match_before_alphabetical_limit() -> None:
    catalog = ResourceCatalog(lambda **_kwargs: [
        resource(f"aaa{index}", "example.io/v1", f"Aaa{index}") for index in range(10)
    ] + [resource("zebras", "example.io/v1", "Zebra")])

    prompt = catalog.prompt_entries(query="which zebras are available?", limit=2)

    assert prompt[0]["resource"] == "zebras"


def test_policy_denies_sensitive_descriptor_even_when_get_is_advertised() -> None:
    descriptor = ResourceDescriptor(
        name="oauthaccesstokens",
        api_version="oauth.openshift.io/v1",
        kind="OAuthAccessToken",
        namespaced=False,
        verbs=("get", "list"),
    )

    assert resource_is_safe(descriptor) is False

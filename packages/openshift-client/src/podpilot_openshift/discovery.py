from __future__ import annotations

import re
from dataclasses import dataclass
from threading import Lock
from time import monotonic
from typing import Callable, Iterable


class ResourceCatalogError(RuntimeError):
    """A safe resource-discovery or resolution failure."""


@dataclass(frozen=True)
class ResourceDescriptor:
    name: str
    api_version: str
    kind: str
    namespaced: bool
    verbs: tuple[str, ...]
    singular_name: str | None = None
    short_names: tuple[str, ...] = ()

    def to_prompt_dict(self, *, qualified: bool = False) -> dict[str, object]:
        group = self.api_version.split("/", 1)[0] if "/" in self.api_version else "core"
        return {
            "resource": f"{self.name}.{group}" if qualified else self.name,
            "apiVersion": self.api_version,
            "kind": self.kind,
            "namespaced": self.namespaced,
            "verbs": list(self.verbs),
        }


_DENIED_NAMES = {
    "secrets",
    "serviceaccounts/token",
    "tokenrequests",
    "tokenreviews",
    "subjectaccessreviews",
    "selfsubjectaccessreviews",
    "selfsubjectrulesreviews",
    "localsubjectaccessreviews",
    "oauthaccesstokens",
    "oauthauthorizetokens",
    "useroauthaccesstokens",
    "identities",
    "users",
    "groups",
}
_DENIED_KINDS = {
    "Secret",
    "TokenRequest",
    "TokenReview",
    "SubjectAccessReview",
    "SelfSubjectAccessReview",
    "SelfSubjectRulesReview",
    "LocalSubjectAccessReview",
    "OAuthAccessToken",
    "OAuthAuthorizeToken",
    "UserOAuthAccessToken",
    "Identity",
    "User",
    "Group",
}


def resource_is_safe(descriptor: ResourceDescriptor) -> bool:
    name = descriptor.name.lower()
    if "/" in name or name in _DENIED_NAMES or descriptor.kind in _DENIED_KINDS:
        return False
    return bool({"get", "list", "watch"}.intersection(descriptor.verbs))


class ResourceCatalog:
    """TTL-cached, policy-filtered Kubernetes/OpenShift API discovery catalog."""

    def __init__(
        self,
        search: Callable[..., Iterable[object]],
        *,
        ttl_seconds: float = 300,
    ) -> None:
        self._search = search
        self._ttl_seconds = ttl_seconds
        self._lock = Lock()
        self._loaded_at = 0.0
        self._entries: tuple[ResourceDescriptor, ...] = ()

    def entries(self) -> tuple[ResourceDescriptor, ...]:
        now = monotonic()
        if self._entries and now - self._loaded_at < self._ttl_seconds:
            return self._entries
        with self._lock:
            now = monotonic()
            if self._entries and now - self._loaded_at < self._ttl_seconds:
                return self._entries
            self._entries = self._discover()
            self._loaded_at = now
            return self._entries

    def invalidate(self) -> None:
        """Discard the bounded catalog so the next read performs fresh discovery."""

        with self._lock:
            self._entries = ()
            self._loaded_at = 0.0

    def _discover(self) -> tuple[ResourceDescriptor, ...]:
        try:
            resources = list(self._search())
        except Exception as exc:
            raise ResourceCatalogError("Kubernetes API discovery is temporarily unavailable.") from exc
        entries: dict[tuple[str, str], ResourceDescriptor] = {}
        for resource in resources:
            # kubernetes.dynamic also returns ResourceList objects. Their
            # __getattr__ performs a live base-resource lookup, so even probing
            # an absent optional attribute can fail discovery for the whole
            # catalog. Read constructor metadata directly and skip list wrappers.
            try:
                stored = vars(resource)
            except TypeError:
                continue
            name = str(stored.get("name") or "")
            kind = str(stored.get("kind") or "")
            group = str(stored.get("group") or "")
            version = str(stored.get("api_version") or "")
            api_version = str(
                stored.get("group_version")
                or (f"{group}/{version}" if group and version else version)
                or ""
            )
            if not name or not kind or not api_version:
                continue
            verbs = tuple(sorted(str(item) for item in (stored.get("verbs") or ())))
            descriptor = ResourceDescriptor(
                name=name,
                api_version=api_version,
                kind=kind,
                namespaced=bool(stored.get("namespaced", False)),
                verbs=verbs,
                singular_name=(str(
                    stored.get("singular_name") or stored.get("singularName") or ""
                ) or None),
                short_names=tuple(str(item) for item in (
                    stored.get("short_names") or stored.get("shortNames") or ()
                )),
            )
            if resource_is_safe(descriptor):
                group = api_version.split("/", 1)[0] if "/" in api_version else "core"
                key = (group, name)
                current = entries.get(key)
                if current is None or _version_rank(api_version) > _version_rank(current.api_version):
                    entries[key] = descriptor
        return tuple(sorted(entries.values(), key=lambda item: (item.name, item.api_version)))

    def resolve(
        self,
        alias: str,
        *,
        verb: str,
        api_version: str | None = None,
        kind: str | None = None,
    ) -> ResourceDescriptor:
        normalized = alias.strip().lower()
        if not normalized or "/" in normalized:
            raise ResourceCatalogError("The requested API resource name is invalid.")
        candidates = []
        for item in self.entries():
            group = item.api_version.split("/", 1)[0] if "/" in item.api_version else "core"
            aliases = {
                item.name.lower(),
                item.kind.lower(),
                *(value.lower() for value in item.short_names),
            }
            if item.singular_name:
                aliases.add(item.singular_name.lower())
            aliases.add(f"{item.name.lower()}.{group.lower()}")
            if normalized in aliases and verb in item.verbs:
                candidates.append(item)
        if not candidates:
            raise ResourceCatalogError(
                f"The requested API resource '{alias[:128]}' is unavailable or outside the read policy."
            )
        if api_version or kind:
            coordinate_matches = [
                item for item in candidates
                if (not api_version or item.api_version == api_version)
                and (not kind or item.kind.casefold() == kind.casefold())
            ]
            if not coordinate_matches:
                available = ", ".join(
                    f"{item.name}.{item.api_version.split('/', 1)[0]} "
                    f"({item.api_version}, {item.kind})"
                    for item in candidates[:5]
                )
                raise ResourceCatalogError(
                    "The requested API resource coordinates do not match the discovered resource. "
                    f"Available choices: {available}."
                )
            candidates = coordinate_matches
        if len(candidates) == 1:
            return candidates[0]
        core = [item for item in candidates if item.api_version == "v1"]
        if len(core) == 1:
            return core[0]
        names = ", ".join(
            f"{item.name}.{item.api_version.split('/', 1)[0]}" for item in candidates[:5]
        )
        raise ResourceCatalogError(
            f"The API resource name '{alias[:128]}' is ambiguous; use one of: {names}."
        )

    def prompt_entries(
        self, *, query: str = "", limit: int = 120
    ) -> list[dict[str, object]]:
        entries = self.entries()
        counts: dict[str, int] = {}
        for item in entries:
            counts[item.name] = counts.get(item.name, 0) + 1
        normalized_query = _normalized_words(query)
        query_terms = _search_terms(query)

        def score(item: ResourceDescriptor) -> tuple[int, int, str, str]:
            aliases = (item.name, item.kind, item.singular_name or "", *item.short_names)
            exact = any(
                alias and _normalized_words(alias) in normalized_query for alias in aliases
            )
            overlap = len(query_terms.intersection(
                term for alias in aliases for term in _search_terms(alias)
            ))
            return (0 if exact else 1 if overlap else 2, -overlap, item.name, item.api_version)

        selected = sorted(entries, key=score)[: max(1, min(limit, 200))]
        return [
            item.to_prompt_dict(qualified=counts[item.name] > 1)
            for item in selected
        ]


def _normalized_words(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _search_terms(value: str) -> set[str]:
    expanded = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", value).lower()
    ignored = {"the", "are", "what", "which", "show", "list", "from", "available"}
    terms = set()
    for term in re.findall(r"[a-z0-9]+", expanded):
        if len(term) < 3 or term in ignored:
            continue
        terms.add(term[:-1] if term.endswith("s") and len(term) > 3 else term)
    return terms


def _version_rank(api_version: str) -> tuple[int, int, int]:
    version = api_version.rsplit("/", 1)[-1].lower()
    match = re.fullmatch(r"v(?P<major>\d+)(?:(?P<stage>alpha|beta)(?P<minor>\d+))?", version)
    if not match:
        return (0, 0, 0)
    stage = match.group("stage")
    stability = 3 if stage is None else 2 if stage == "beta" else 1
    return (stability, int(match.group("major")), int(match.group("minor") or 0))

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Callable

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from kubernetes.dynamic import DynamicClient

from podpilot_diagnostics.remediation import (
    ActionProposal,
    ActionResult,
    ActionValidation,
    PROTECTED_NAMESPACES,
)


class RemediationError(RuntimeError):
    pass


class KubernetesRemediationExecutor:
    def __init__(
        self,
        *,
        core_api: client.CoreV1Api | None = None,
        dynamic_client: DynamicClient | None = None,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._core = core_api
        self._dynamic = dynamic_client
        self._sleep = sleep
        self._now = now

    def _ensure_clients(self) -> None:
        if self._core is not None and self._dynamic is not None:
            return
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        api_client = client.ApiClient()
        self._core = client.CoreV1Api(api_client)
        self._dynamic = DynamicClient(api_client)

    def preview(self, proposal: ActionProposal) -> dict[str, object]:
        self._require_registered_scope(proposal)
        self._ensure_clients()
        if proposal.action_type == "delete_controller_owned_pod":
            return self._preview_pod_delete(proposal)
        if proposal.action_type == "restart_workload_rollout":
            return self._preview_rollout(proposal)
        raise RemediationError("The requested action type is not registered.")

    def validate(self, proposal: ActionProposal) -> ActionValidation:
        """Re-read exact identity without performing even a dry-run mutation."""
        try:
            self._require_registered_scope(proposal)
            self._ensure_clients()
            if proposal.action_type == "delete_controller_owned_pod":
                assert self._core is not None
                target = self._core.read_namespaced_pod(
                    proposal.target_name, proposal.namespace
                )
                self._require_identity(target, proposal)
                if not self._controlled_by(target, proposal.direct_owner_uid):
                    raise RemediationError("The Pod controller changed.")
            elif proposal.action_type == "restart_workload_rollout":
                _, target = self._workload(proposal)
                self._require_identity(target, proposal)
            else:
                raise RemediationError("The requested action type is not registered.")
            return ActionValidation("current", "The exact target identity is still current.")
        except RemediationError as exc:
            return ActionValidation("stale", str(exc))
        except ApiException as exc:
            if exc.status == 404:
                return ActionValidation("missing", "The exact target no longer exists.")
            return ActionValidation(
                "unavailable",
                f"The Kubernetes API could not validate the target ({exc.status or 'error'}).",
            )
        except Exception as exc:
            return ActionValidation(
                "unavailable",
                f"The target could not be validated ({type(exc).__name__}).",
            )

    def execute(self, proposal: ActionProposal) -> ActionResult:
        try:
            self._require_registered_scope(proposal)
            self._ensure_clients()
            if self._now() > proposal.expires_at:
                return self._result("stale", "The approval window expired before execution.")
            if proposal.action_type == "delete_controller_owned_pod":
                return self._execute_pod_delete(proposal)
            if proposal.action_type == "restart_workload_rollout":
                return self._execute_rollout(proposal)
            raise RemediationError("The requested action type is not registered.")
        except RemediationError as exc:
            return self._result("stale", str(exc))
        except Exception as exc:
            return self._result(
                "failed",
                f"The Kubernetes operation failed ({type(exc).__name__}).",
            )

    def _preview_pod_delete(self, proposal: ActionProposal) -> dict[str, object]:
        assert self._core is not None
        pod = self._core.read_namespaced_pod(proposal.target_name, proposal.namespace)
        self._require_identity(pod, proposal)
        if not self._controlled_by(pod, proposal.direct_owner_uid):
            raise RemediationError("The Pod controller changed; generate a fresh preview before approval.")
        self._core.delete_namespaced_pod(
            proposal.target_name,
            proposal.namespace,
            body=client.V1DeleteOptions(
                dry_run=["All"],
                preconditions=client.V1Preconditions(
                    uid=proposal.target_uid,
                    resource_version=proposal.target_resource_version,
                )
            ),
            dry_run="All",
            grace_period_seconds=30,
        )
        return {
            "server_dry_run": "passed",
            "target_observed": self._identity(pod),
            "operation": proposal.operation,
        }

    def _preview_rollout(self, proposal: ActionProposal) -> dict[str, object]:
        resource, workload = self._workload(proposal)
        self._require_identity(workload, proposal)
        resource.patch(
            name=proposal.target_name,
            namespace=proposal.namespace,
            body=self._rollout_patch(proposal),
            content_type="application/merge-patch+json",
            dry_run="All",
        )
        return {
            "server_dry_run": "passed",
            "target_observed": self._identity(workload),
            "operation": proposal.operation,
        }

    def _execute_pod_delete(self, proposal: ActionProposal) -> ActionResult:
        assert self._core is not None
        pod = self._core.read_namespaced_pod(proposal.target_name, proposal.namespace)
        self._require_identity(pod, proposal)
        if not self._controlled_by(pod, proposal.direct_owner_uid):
            raise RemediationError("The Pod controller changed; generate a fresh preview before approval.")
        before = self._identity(pod)
        existing_uids = {
            str(item.metadata.uid)
            for item in (self._core.list_namespaced_pod(proposal.namespace, limit=200).items or [])
            if self._controlled_by(item, proposal.direct_owner_uid)
        }
        response = self._core.delete_namespaced_pod(
            proposal.target_name,
            proposal.namespace,
            body=client.V1DeleteOptions(
                preconditions=client.V1Preconditions(
                    uid=proposal.target_uid,
                    resource_version=proposal.target_resource_version,
                )
            ),
            grace_period_seconds=30,
        )
        deadline = time.monotonic() + proposal.verification_timeout_seconds
        replacement: Any | None = None
        while time.monotonic() < deadline:
            pods = self._core.list_namespaced_pod(proposal.namespace, limit=200).items or []
            replacement = next(
                (
                    item
                    for item in pods
                    if str(item.metadata.uid) not in existing_uids
                    and self._controlled_by(item, proposal.direct_owner_uid)
                    and self._pod_ready(item)
                ),
                None,
            )
            if replacement is not None:
                break
            self._sleep(2)
        if replacement is None:
            return ActionResult(
                outcome="unresolved",
                summary="The old Pod was deleted, but no Ready controller replacement appeared before timeout.",
                before=before,
                api_result={"accepted": True, "status": str(getattr(response, "status", "Success"))[:64]},
                verification={"old_uid_absent_or_terminating": True, "replacement_ready": False},
                after={},
            )
        return ActionResult(
            outcome="resolved",
            summary="The controller replaced the failed Pod and the replacement became Ready.",
            before=before,
            api_result={"accepted": True, "status": str(getattr(response, "status", "Success"))[:64]},
            verification={"old_uid_replaced": True, "replacement_ready": True},
            after=self._identity(replacement),
        )

    def _execute_rollout(self, proposal: ActionProposal) -> ActionResult:
        resource, workload = self._workload(proposal)
        self._require_identity(workload, proposal)
        before = self._identity(workload)
        response = resource.patch(
            name=proposal.target_name,
            namespace=proposal.namespace,
            body=self._rollout_patch(proposal),
            content_type="application/merge-patch+json",
        )
        deadline = time.monotonic() + proposal.verification_timeout_seconds
        latest = response
        verified = False
        while time.monotonic() < deadline:
            latest = resource.get(name=proposal.target_name, namespace=proposal.namespace)
            metadata = latest.metadata
            spec = getattr(latest, "spec", None)
            status = getattr(latest, "status", None)
            template = getattr(spec, "template", None)
            template_metadata = getattr(template, "metadata", None)
            annotations = getattr(template_metadata, "annotations", None) or {}
            if proposal.target_kind == "DaemonSet":
                desired = int(getattr(status, "desiredNumberScheduled", 0) or 0)
                updated = int(getattr(status, "updatedNumberScheduled", 0) or 0)
                ready = int(getattr(status, "numberReady", 0) or 0)
            else:
                desired = int(getattr(spec, "replicas", 1) or 0)
                updated = int(getattr(status, "updatedReplicas", 0) or 0)
                ready = int(getattr(status, "readyReplicas", 0) or 0)
            generation = int(getattr(metadata, "generation", 0) or 0)
            observed = int(getattr(status, "observedGeneration", 0) or 0)
            verified = (
                annotations.get("podpilot.io/restartedAt") == proposal.rollout_annotation
                and updated >= desired
                and ready >= desired
                and observed >= generation
            )
            if verified:
                break
            self._sleep(2)
        return ActionResult(
            outcome="resolved" if verified else "unresolved",
            summary=(
                "The restarted workload reached its desired updated and Ready replica count."
                if verified
                else "The restart was accepted, but the workload did not become fully updated and Ready before timeout."
            ),
            before=before,
            api_result={"accepted": True},
            verification={"rollout_ready": verified, "annotation_observed": proposal.rollout_annotation},
            after=self._identity(latest),
        )

    def _workload(self, proposal: ActionProposal):
        assert self._dynamic is not None
        resource = self._dynamic.resources.get(
            api_version=proposal.target_api_version,
            kind=proposal.target_kind,
        )
        return resource, resource.get(name=proposal.target_name, namespace=proposal.namespace)

    @staticmethod
    def _require_registered_scope(proposal: ActionProposal) -> None:
        protected = (
            proposal.namespace in PROTECTED_NAMESPACES
            or proposal.namespace.startswith("openshift-")
            or proposal.namespace.startswith("kube-")
        )
        if protected:
            raise RemediationError("Registered remediation is disabled in protected system namespaces.")
        if proposal.action_type == "delete_controller_owned_pod":
            valid = (
                proposal.target_api_version == "v1"
                and proposal.target_kind == "Pod"
                and bool(proposal.direct_owner_uid)
            )
        elif proposal.action_type == "restart_workload_rollout":
            valid = (
                proposal.target_api_version == "apps/v1"
                and proposal.target_kind in {"Deployment", "StatefulSet", "DaemonSet"}
                and bool(proposal.rollout_annotation)
            )
        else:
            valid = False
        if not valid:
            raise RemediationError("The requested target is outside the registered remediation scope.")

    @staticmethod
    def _rollout_patch(proposal: ActionProposal) -> dict[str, object]:
        return {
            "metadata": {
                "uid": proposal.target_uid,
                "resourceVersion": proposal.target_resource_version,
            },
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {"podpilot.io/restartedAt": proposal.rollout_annotation}
                    }
                }
            },
        }

    @staticmethod
    def _identity(resource: Any) -> dict[str, object]:
        metadata = resource.metadata
        return {
            "name": str(metadata.name)[:253],
            "uid": str(metadata.uid)[:128],
            "resource_version": str(
                getattr(metadata, "resource_version", None)
                or getattr(metadata, "resourceVersion", "")
            )[:128],
        }

    @classmethod
    def _require_identity(cls, resource: Any, proposal: ActionProposal) -> None:
        identity = cls._identity(resource)
        if (
            identity["uid"] != proposal.target_uid
            or identity["resource_version"] != proposal.target_resource_version
        ):
            raise RemediationError(
                "The target UID or resourceVersion changed; generate a fresh preview before approval."
            )

    @staticmethod
    def _controlled_by(pod: Any, owner_uid: str | None) -> bool:
        return bool(owner_uid) and any(
            bool(getattr(item, "controller", False)) and str(getattr(item, "uid", "")) == owner_uid
            for item in (getattr(pod.metadata, "owner_references", None) or [])
        )

    @staticmethod
    def _pod_ready(pod: Any) -> bool:
        return any(
            str(getattr(item, "type", "")) == "Ready" and str(getattr(item, "status", "")) == "True"
            for item in (getattr(pod.status, "conditions", None) or [])
        )

    @staticmethod
    def _result(outcome: str, summary: str) -> ActionResult:
        return ActionResult(
            outcome=outcome,  # type: ignore[arg-type]
            summary=summary,
            before={},
            api_result={},
            verification={},
            after={},
        )

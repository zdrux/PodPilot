from datetime import datetime, timezone
from types import SimpleNamespace

from podpilot_openshift.workloads import KubernetesWorkloadClient


def ns(**values):
    return SimpleNamespace(**values)


class FakeCoreApi:
    def read_namespaced_pod(self, name, namespace):
        waiting = ns(reason="CrashLoopBackOff", message="password=do-not-retain")
        terminated = ns(reason="Error", exit_code=1)
        status = ns(
            name="api",
            image="registry.example/api:v1",
            ready=False,
            restart_count=7,
            state=ns(waiting=waiting),
            last_state=ns(terminated=terminated),
        )
        return ns(
            metadata=ns(
                uid="pod-uid",
                owner_references=[
                    ns(controller=True, api_version="apps/v1", kind="ReplicaSet", name="api-abc")
                ],
            ),
            status=ns(
                phase="Running",
                container_statuses=[status],
                conditions=[ns(type="Ready", status="False", reason="ContainersNotReady")],
            ),
            spec=ns(
                node_name="worker-0",
                containers=[ns(resources=ns(requests={"cpu": "100m", "memory": "64Mi"}))],
            ),
        )

    def list_namespaced_event(self, namespace, field_selector, limit):
        return ns(
            items=[
                ns(
                    metadata=ns(
                        uid="event-uid",
                        name="backoff.123",
                        creation_timestamp=datetime(2026, 8, 23, tzinfo=timezone.utc),
                    ),
                    event_time=None,
                    last_timestamp=None,
                    reason="BackOff",
                    message="token=do-not-retain",
                    type="Warning",
                )
            ]
        )

    def list_node(self, limit):
        return ns(
            items=[
                ns(
                    metadata=ns(name="worker-0"),
                    status=ns(allocatable={"cpu": "8", "memory": "24Gi", "pods": "250"}),
                    spec=ns(
                        taints=[ns(key="dedicated", value="infra", effect="NoSchedule")],
                        unschedulable=False,
                    ),
                )
            ]
        )

    def read_namespaced_pod_log(
        self, name, namespace, *, container, previous, tail_lines, timestamps, _request_timeout
    ):
        return "Authorization: Bearer abc.def.ghi" if previous else "server starting"


class FakeResource:
    def get(self, *, name, namespace):
        return ns(
            metadata=ns(ownerReferences=[]),
            spec=ns(replicas=1),
            status=ns(readyReplicas=0, updatedReplicas=1),
        )


class FakeResources:
    def get(self, *, api_version, kind):
        return FakeResource()


class FakeDynamicClient:
    resources = FakeResources()


def test_workload_client_collects_bounded_redacted_evidence() -> None:
    source = KubernetesWorkloadClient(
        core_api=FakeCoreApi(),
        dynamic_client=FakeDynamicClient(),
        max_events=10,
        max_log_bytes=1024,
    )
    evidence = source.collect(
        namespace="demo",
        pod_name="api-abc-123",
        container_name="api",
        include_logs=True,
        include_nodes=True,
    )

    assert evidence.containers[0].reason == "CrashLoopBackOff"
    assert evidence.containers[0].message == "password=[REDACTED]"
    assert evidence.events[0].message == "token=[REDACTED]"
    assert evidence.previous_logs["api"].endswith("[REDACTED]")
    assert evidence.owners[0].kind == "ReplicaSet"
    assert evidence.nodes[0].allocatable["cpu"] == "8"
    assert evidence.failures == ()

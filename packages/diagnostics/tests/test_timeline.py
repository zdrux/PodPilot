from podpilot_diagnostics.timeline import memory_timeline
from podpilot_diagnostics.adhoc import ReadIntent
import pytest


def test_memory_timeline_requires_uid_and_uses_occurrence_not_collection_time():
    data = {"namespace": "payments", "name": "worker", "start": "2026-09-09T00:00:00Z", "end": "2026-09-09T01:00:00Z"}
    pod = {"metadata": {"namespace": "payments", "name": "worker", "uid": "new-uid"},
           "status": {"containerStatuses": [{"name": "app", "lastState": {"terminated": {
               "reason": "OOMKilled", "finishedAt": "2026-09-09T00:20:00Z"}}}]}}
    events = [{"metadata": {"name": "worker.failed", "uid": "event-uid", "creationTimestamp": "2026-09-09T00:30:00Z"},
               "involvedObject": {"kind": "Pod", "name": "worker", "uid": "new-uid"},
               "reason": "BackOff", "lastTimestamp": "2026-09-09T00:21:00Z"},
              {"involvedObject": {"kind": "Pod", "name": "worker", "uid": "old-uid"},
               "reason": "Evicted", "lastTimestamp": "2026-09-09T00:22:00Z"}]
    timeline = memory_timeline(data, pod, events)
    assert [m["reason"] for m in timeline["markers"]] == ["OOMKilled", "BackOff"]
    assert timeline["markers"][1]["timestamp"] == "2026-09-09T00:21:00+00:00"
    assert "event-uid" in timeline["markers"][1]["source"]
    assert all(m["pod_uid"] == "new-uid" for m in timeline["markers"])
    assert "without Pod UID" in " ".join(timeline["limitations"])
    pod["metadata"].pop("uid")
    assert memory_timeline(data, pod, events)["markers"] == []


def test_timeline_intent_is_exact_and_bounded_to_supported_metrics():
    with pytest.raises(ValueError, match="exact namespace/Pod"):
        ReadIntent(tool="query_metrics", metric="memory_working_set", metric_scope="cluster", include_timeline=True)
    intent = ReadIntent(tool="query_metrics", metric="memory_working_set", metric_scope="pod",
                        kind="Pod", namespace="payments", name="worker", include_timeline=True)
    assert intent.include_timeline

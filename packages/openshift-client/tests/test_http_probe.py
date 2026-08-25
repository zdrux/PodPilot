import ssl

from podpilot_diagnostics.adhoc import ReadIntent
from podpilot_openshift.http_probe import BoundedHttpProbe


class FakeSocket:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.sent = b""
        self.closed = False

    def settimeout(self, _timeout: float) -> None:
        pass

    def sendall(self, value: bytes) -> None:
        self.sent += value

    def recv(self, size: int) -> bytes:
        value, self.response = self.response[:size], self.response[size:]
        return value

    def getpeercert(self):
        return {"subjectAltName": (("DNS", "route.apps.example.test"),)}

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def close(self) -> None:
        self.closed = True


class FakeTlsContext:
    def __init__(self, *, failure: Exception | None = None) -> None:
        self.failure = failure
        self.server_name = None
        self.protocols = []

    def load_verify_locations(self, *, cafile: str) -> None:
        pass

    def set_alpn_protocols(self, protocols: list[str]) -> None:
        self.protocols = protocols

    def wrap_socket(self, stream, *, server_hostname: str):
        self.server_name = server_hostname
        if self.failure:
            raise self.failure
        return stream


def resolver(host, port, *, type):
    assert host == "192.0.2.50"
    assert port == 443
    return [(2, type, 6, "", ("192.0.2.50", port))]


def test_https_probe_uses_url_hostname_for_sni_and_host_with_connection_override() -> None:
    stream = FakeSocket(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: secret=yes\r\n\r\nhealthy"
    )
    context = FakeTlsContext()
    connections = []
    probe = BoundedHttpProbe(
        resolver=resolver,
        connector=lambda address, timeout: connections.append((address, timeout)) or stream,
        ssl_context_factory=lambda: context,
    )

    result = probe.execute(ReadIntent(
        tool="http_probe",
        url="https://route.apps.example.test/ready?full=1",
        connect_host="192.0.2.50",
        method="GET",
    ))

    observation = result.observations[0]
    assert context.server_name == "route.apps.example.test"
    assert context.protocols == ["http/1.1"]
    assert connections[0][0] == ("192.0.2.50", 443)
    assert b"GET /ready?full=1 HTTP/1.1" in stream.sent
    assert b"Host: route.apps.example.test" in stream.sent
    assert observation.data["statusCode"] == 200
    assert observation.data["tls"]["serverName"] == "route.apps.example.test"
    assert observation.data["bodySample"] == "healthy"
    assert "set-cookie" not in observation.data["headers"]


def test_tls_verification_failure_is_retained_as_evidence() -> None:
    stream = FakeSocket(b"")
    context = FakeTlsContext(failure=ssl.SSLCertVerificationError("unknown CA"))
    probe = BoundedHttpProbe(
        resolver=resolver,
        connector=lambda _address, _timeout: stream,
        ssl_context_factory=lambda: context,
    )

    result = probe.execute(ReadIntent(
        tool="http_probe",
        url="https://route.apps.example.test/",
        connect_host="192.0.2.50",
    ))

    assert result.observations[0].data["outcome"] == "failed"
    assert result.observations[0].data["stage"] == "tls"
    assert "unknown CA" in result.limitations[0]


def test_https_probe_can_bypass_verification_without_changing_sni() -> None:
    stream = FakeSocket(b"HTTP/1.1 200 OK\r\n\r\n")
    context = FakeTlsContext()
    probe = BoundedHttpProbe(
        resolver=resolver,
        connector=lambda _address, _timeout: stream,
        ssl_context_factory=lambda: context,
    )

    result = probe.execute(ReadIntent(
        tool="http_probe",
        url="https://route.apps.example.test/",
        connect_host="192.0.2.50",
        tls_verify=False,
    ))

    assert context.server_name == "route.apps.example.test"
    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE
    assert result.observations[0].data["tls"]["verified"] is False
    assert result.observations[0].data["tls"]["verificationMode"] == "insecure"
    assert "does not prove server identity" in result.limitations[0]

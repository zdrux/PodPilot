from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from podpilot_diagnostics.adhoc import AdHocObservation, ReadIntent, ReadResult
from podpilot_diagnostics.redaction import redact_text


Resolver = Callable[..., list[tuple[object, ...]]]
Connector = Callable[[tuple[str, int], float], socket.socket]


class BoundedHttpProbe:
    """Perform one unauthenticated, verified, bounded HTTP/HTTPS observation."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 8.0,
        max_response_bytes: int = 16_384,
        additional_ca_path: Path | None = None,
        resolver: Resolver = socket.getaddrinfo,
        connector: Connector = socket.create_connection,
        ssl_context_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context,
    ) -> None:
        self._timeout = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._additional_ca_path = additional_ca_path
        self._resolver = resolver
        self._connector = connector
        self._ssl_context_factory = ssl_context_factory

    def execute(self, intent: ReadIntent) -> ReadResult:
        if intent.tool != "http_probe" or not intent.url:
            raise ValueError("BoundedHttpProbe requires an http_probe intent.")
        parsed = urlsplit(intent.url)
        logical_host = parsed.hostname
        assert logical_host is not None
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        connect_host = intent.connect_host or logical_host
        display_url = urlunsplit((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            "[REDACTED]" if parsed.query else "",
            "",
        ))
        started = time.monotonic()
        resolved: list[str] = []
        stage = "dns"
        stream = None
        tls: dict[str, object] | None = None
        try:
            addresses = self._resolver(connect_host, port, type=socket.SOCK_STREAM)
            resolved = list(dict.fromkeys(
                str(item[4][0]) for item in addresses if len(item) > 4 and item[4]
            ))[:12]
            if not resolved:
                raise OSError("DNS returned no addresses")
            stage = "connect"
            stream = self._connector((resolved[0], port), self._timeout)
            stream.settimeout(self._timeout)
            if parsed.scheme == "https":
                stage = "tls"
                context = self._ssl_context_factory()
                if self._additional_ca_path and self._additional_ca_path.is_file():
                    context.load_verify_locations(cafile=str(self._additional_ca_path))
                context.set_alpn_protocols(["http/1.1"])
                stream = context.wrap_socket(stream, server_hostname=logical_host)
                certificate = stream.getpeercert() or {}
                tls = {
                    "verified": True,
                    "serverName": logical_host,
                    "version": stream.version(),
                    "cipher": (stream.cipher() or (None,))[0],
                    "subjectAltNames": [
                        str(value)[:253]
                        for kind, value in certificate.get("subjectAltName", ())
                        if kind == "DNS"
                    ][:20],
                }
            stage = "http"
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"
            default_port = 443 if parsed.scheme == "https" else 80
            try:
                header_host = f"[{logical_host}]" if ipaddress.ip_address(logical_host).version == 6 else logical_host
            except ValueError:
                header_host = logical_host
            host_header = header_host if port == default_port else f"{header_host}:{port}"
            request = (
                f"{intent.method} {path} HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                "User-Agent: PodPilot/1.0 read-only-probe\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii", errors="strict")
            stream.sendall(request)
            response = bytearray()
            while len(response) < self._max_response_bytes:
                chunk = stream.recv(min(4096, self._max_response_bytes - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
            header_bytes, separator, body = bytes(response).partition(b"\r\n\r\n")
            header_lines = header_bytes.decode("iso-8859-1", errors="replace").splitlines()
            status_line = header_lines[0] if header_lines else ""
            parts = status_line.split(" ", 2)
            status_code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
            selected_headers: dict[str, str] = {}
            allowed_headers = {"content-type", "content-length", "location", "server"}
            for line in header_lines[1:]:
                name, marker, value = line.partition(":")
                lowered = name.strip().lower()
                if marker and lowered in allowed_headers:
                    selected_headers[lowered] = redact_text(value.strip())[:500]
            elapsed_ms = round((time.monotonic() - started) * 1000, 1)
            data: dict[str, object] = {
                "outcome": "response_received",
                "url": display_url,
                "method": intent.method,
                "logicalHost": logical_host,
                "connectHost": connect_host,
                "resolvedAddresses": resolved,
                "port": port,
                "statusCode": status_code,
                "statusLine": redact_text(status_line)[:200],
                "headers": selected_headers,
                "bodySample": redact_text(body.decode("utf-8", errors="replace"))[:4096]
                if separator and intent.method == "GET" else "",
                "responseTruncated": len(response) >= self._max_response_bytes,
                "redirectFollowed": False,
                "elapsedMs": elapsed_ms,
                "tls": tls,
            }
            return ReadResult(observations=(AdHocObservation(
                id=f"network-{uuid4()}",
                tool="http_probe",
                summary=f"{intent.method} {logical_host} returned {status_code or 'an HTTP response'}.",
                source=f"{display_url} via {connect_host}:{port}",
                collected_at=datetime.now(timezone.utc),
                data=data,
            ),))
        except (OSError, ssl.SSLError, ValueError, UnicodeError) as exc:
            elapsed_ms = round((time.monotonic() - started) * 1000, 1)
            safe_error = redact_text(str(exc))[:500] or type(exc).__name__
            return ReadResult(
                observations=(AdHocObservation(
                    id=f"network-{uuid4()}",
                    tool="http_probe",
                    summary=f"HTTP probe to {logical_host} failed during {stage}.",
                    source=f"{display_url} via {connect_host}:{port}",
                    collected_at=datetime.now(timezone.utc),
                    data={
                        "outcome": "failed",
                        "stage": stage,
                        "url": display_url,
                        "method": intent.method,
                        "logicalHost": logical_host,
                        "connectHost": connect_host,
                        "resolvedAddresses": resolved,
                        "port": port,
                        "error": safe_error,
                        "elapsedMs": elapsed_ms,
                        "tls": tls,
                    },
                ),),
                limitations=(f"The HTTP probe failed during {stage}: {safe_error}",),
            )
        finally:
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

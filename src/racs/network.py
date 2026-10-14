"""Single bounded outbound implementation; never honors environment proxies."""

import asyncio
import ssl
from dataclasses import dataclass

import dns.asyncresolver
import dns.exception
import h11

from racs.scope import PolicyError, Scope, public_ip


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes


class Resolver:
    async def addresses(self, host: str) -> list[str]:
        result = []
        resolver = dns.asyncresolver.Resolver()
        for kind in ("A", "AAAA"):
            try:
                answer = await resolver.resolve(host, kind, lifetime=3, search=False)
                result.extend(str(item) for item in answer)
            except dns.resolver.NoAnswer:
                pass
            except dns.exception.DNSException as exc:
                raise PolicyError("DNS resolution failed") from exc
        if not result or len(result) > 32:
            raise PolicyError("DNS returned no usable addresses or too many addresses")
        return [public_ip(ip) for ip in result]

    async def txt(self, host: str) -> list[str]:
        try:
            answer = await dns.asyncresolver.Resolver().resolve(
                f"_racs-verify.{host}", "TXT", lifetime=3, search=False
            )
            records = [b"".join(item.strings).decode("ascii") for item in answer]
        except (dns.exception.DNSException, UnicodeError) as exc:
            raise PolicyError("TXT proof could not be read") from exc
        if len(records) > 32 or any(len(record) > 4096 for record in records):
            raise PolicyError("TXT proof exceeds limits")
        return records


class Outbound:
    def __init__(self, resolver=None):
        self.resolver = resolver or Resolver()
        self._slots = asyncio.Semaphore(2)

    async def addresses(self, scope: Scope) -> list[str]:
        # Revalidate injected resolver results as well as real DNS responses.
        values = await self.resolver.addresses(scope.host)
        if not values or len(values) > 32:
            raise PolicyError("Invalid DNS address set")
        return [public_ip(value) for value in values]

    async def proof(self, scope: Scope, method: str) -> list[str]:
        async with self._slots, asyncio.timeout(10):
            addresses = await self.addresses(scope)
            if method == "dns":
                return await self.resolver.txt(scope.host)
            if method != "https":
                raise PolicyError("Unsupported proof method")
            try:
                response = await self._get(scope, addresses[0], "/.well-known/racs-verify.txt")
            except h11.RemoteProtocolError as exc:
                raise PolicyError("Malformed verification response") from exc
            if response.status != 200:
                raise PolicyError("Proof file must return 200 without redirects")
            try:
                return [response.body.decode("ascii").strip()]
            except UnicodeError as exc:
                raise PolicyError("Proof file must be ASCII text") from exc

    async def _get(self, scope: Scope, address: str, path: str) -> Response:
        public_ip(address)
        # Numeric connection address prevents a second DNS lookup. SNI and certificate
        # validation still use the original hostname; proxies are never consulted.
        reader, writer = await asyncio.open_connection(
            host=address,
            port=443,
            ssl=ssl.create_default_context(),
            server_hostname=scope.host,
            ssl_handshake_timeout=4,
            limit=16384,
        )
        try:
            peer = writer.get_extra_info("peername")
            if not peer or public_ip(peer[0]) != address:
                raise PolicyError("Connected peer differs from approved destination")
            conn = h11.Connection(h11.CLIENT, max_incomplete_event_size=16384)
            writer.write(
                conn.send(
                    h11.Request(
                        method="GET",
                        target=path,
                        headers=[
                            ("Host", scope.host),
                            ("User-Agent", "RACS/0.1 ownership-verification"),
                            ("Accept-Encoding", "identity"),
                            ("Connection", "close"),
                        ],
                    )
                )
            )
            writer.write(conn.send(h11.EndOfMessage()))
            await writer.drain()
            body = bytearray()
            status = None
            wire_bytes = 0
            while True:
                event = conn.next_event()
                if event is h11.NEED_DATA:
                    data = await reader.read(4096)
                    wire_bytes += len(data)
                    if wire_bytes > 65536:
                        raise PolicyError("Response exceeds wire limit")
                    conn.receive_data(data)
                elif isinstance(event, h11.Response):
                    status = event.status_code
                    if status != 200:
                        return Response(status, b"")
                    if any(
                        k == b"content-encoding" and v.lower() != b"identity"
                        for k, v in event.headers
                    ):
                        raise PolicyError("Compressed proof files are not accepted")
                elif isinstance(event, h11.Data):
                    body.extend(event.data)
                    if len(body) > 4096:
                        raise PolicyError("Proof file exceeds 4096 bytes")
                elif isinstance(event, h11.EndOfMessage):
                    return Response(status or 0, bytes(body))
                elif isinstance(event, h11.ConnectionClosed):
                    raise PolicyError("Incomplete response")
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except (TimeoutError, OSError):
                pass

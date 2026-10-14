import asyncio
import ssl
from unittest.mock import AsyncMock, MagicMock

import pytest

from racs.network import Outbound, Resolver, Response
from racs.scope import PolicyError, Scope


def outbound(addresses=None):
    resolver = MagicMock()
    resolver.addresses = AsyncMock(return_value=addresses or ["8.8.8.8"])
    resolver.txt = AsyncMock(return_value=["racs-v1=proof"])
    return Outbound(resolver)


async def test_dns_success_and_mixed_private_denial():
    net = outbound()
    assert await net.proof(Scope.parse("example.com"), "dns") == ["racs-v1=proof"]
    net = outbound(["8.8.8.8", "127.0.0.1"])
    with pytest.raises(PolicyError):
        await net.proof(Scope.parse("example.com"), "dns")
    net.resolver.txt.assert_not_called()


@pytest.mark.parametrize("status", [301, 302, 307, 308, 404, 429, 503])
async def test_https_redirects_and_failures_rejected(status):
    net = outbound()
    net._get = AsyncMock(return_value=Response(status, b"racs-v1=proof"))
    with pytest.raises(PolicyError):
        await net.proof(Scope.parse("example.com"), "https")
    net._get.assert_awaited_once()


def mock_stream(monkeypatch, raw, peer="8.8.8.8"):
    reader = AsyncMock()
    reader.read.side_effect = [raw, b""]
    writer = MagicMock()
    writer.get_extra_info.return_value = (peer, 443)
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    connect = AsyncMock(return_value=(reader, writer))
    monkeypatch.setattr(asyncio, "open_connection", connect)
    return connect, writer


async def test_pinned_connection_tls_and_proxy_independence(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
    body = b"racs-v1=proof\n"
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    connect, writer = mock_stream(monkeypatch, raw)
    net = outbound()
    assert await net.proof(Scope.parse("example.com"), "https") == ["racs-v1=proof"]
    args = connect.call_args.kwargs
    assert args["host"] == "8.8.8.8"
    assert args["server_hostname"] == "example.com"
    assert args["ssl"].verify_mode == ssl.CERT_REQUIRED
    assert args["ssl"].check_hostname
    assert b"Host: example.com" in writer.write.call_args_list[0].args[0]
    writer.close.assert_called_once()


async def test_peer_mismatch(monkeypatch):
    mock_stream(monkeypatch, b"", peer="1.1.1.1")
    with pytest.raises(PolicyError, match="differs"):
        await outbound().proof(Scope.parse("example.com"), "https")


@pytest.mark.parametrize(
    "raw",
    [
        b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n" + b"x" * 5000,
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
    ],
)
async def test_bounded_response(monkeypatch, raw):
    mock_stream(monkeypatch, raw)
    with pytest.raises(PolicyError):
        await outbound().proof(Scope.parse("example.com"), "https")


async def test_dns_rebinding_rechecked(monkeypatch):
    net = outbound()
    net.resolver.addresses.side_effect = [["8.8.8.8"], ["10.0.0.1"]]
    assert await net.proof(Scope.parse("example.com"), "dns")
    with pytest.raises(PolicyError):
        await net.proof(Scope.parse("example.com"), "dns")


async def test_real_dns_adapter_uses_all_families_and_txt(monkeypatch):
    resolver = MagicMock()
    txt = MagicMock(strings=[b"racs-v1=", b"proof"])
    resolver.resolve = AsyncMock(side_effect=[["8.8.8.8"], ["2606:4700:4700::1111"], [txt]])
    monkeypatch.setattr("dns.asyncresolver.Resolver", lambda: resolver)
    net = Resolver()
    assert len(await net.addresses("example.com")) == 2
    assert await net.txt("example.com") == ["racs-v1=proof"]
    assert resolver.resolve.call_args.args == ("_racs-verify.example.com", "TXT")

import socket

import pytest


@pytest.fixture(autouse=True)
def no_external_network(monkeypatch):
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def local_connect(sock, address):
        if isinstance(address, tuple) and address[0] in ("127.0.0.1", "::1"):
            return original_connect(sock, address)
        raise AssertionError("External network disabled in tests")

    def local_connect_ex(sock, address):
        if isinstance(address, tuple) and address[0] in ("127.0.0.1", "::1"):
            return original_connect_ex(sock, address)
        raise AssertionError("External network disabled in tests")

    def blocked(*args, **kwargs):
        raise AssertionError("Tests must not make real network connections")

    monkeypatch.setattr(socket.socket, "connect", local_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", local_connect_ex)
    monkeypatch.setattr(socket.socket, "sendto", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


def pytest_addoption(parser):
    parser.addoption(
        "--run-practice",
        action="store_true",
        help="Run real loopback TLS practice target and browser checks",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "practice: local real-server/browser validation")


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--run-practice"):
        for item in items:
            if "practice" in item.keywords:
                item.add_marker(
                    pytest.mark.skip(reason="Use --run-practice for isolated local target tests")
                )

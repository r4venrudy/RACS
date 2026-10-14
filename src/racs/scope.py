"""Conservative scope: exact HTTPS origin, root path, port 443 only."""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit


class PolicyError(ValueError):
    pass


def public_ip(value: str) -> str:
    address = ipaddress.ip_address(value)
    if address.version == 6 and any(
        address in ipaddress.ip_network(net) for net in ("64:ff9b::/96", "64:ff9b:1::/48")
    ):
        raise PolicyError("Address translation destinations are disabled")
    if (
        not address.is_global
        or address.is_multicast
        or address.is_reserved
        or getattr(address, "ipv4_mapped", None)
        or (address.version == 6 and (address.sixtofour or address.teredo))
    ):
        raise PolicyError("Destination is not a permitted public unicast address")
    return str(address)


@dataclass(frozen=True)
class Scope:
    host: str
    port: int = 443

    @property
    def origin(self) -> str:
        return f"https://{self.host}" + (f":{self.port}" if self.port != 443 else "")

    @classmethod
    def parse(cls, value: str, *, allow_lab=False) -> "Scope":
        if not isinstance(value, str) or not value or len(value) > 2048:
            raise PolicyError("Supply an HTTPS hostname")
        if any(ord(c) <= 32 or ord(c) >= 127 for c in value) or "\\" in value:
            raise PolicyError("Use an ASCII hostname (IDNA form for international names)")
        if allow_lab and value in (
            "https://racs-lab.localhost:9443",
            "https://racs-lab.localhost:9443/",
        ):
            return cls("racs-lab.localhost", 9443)
        url = urlsplit(value if "://" in value else f"https://{value}")
        try:
            port = url.port
        except ValueError as exc:
            raise PolicyError("Invalid port") from exc
        host = (url.hostname or "").lower()
        if (
            url.scheme != "https"
            or port not in (None, 443)
            or url.username is not None
            or url.password is not None
            or url.path not in ("", "/")
            or url.query
            or url.fragment
            or "?" in value
            or "#" in value
        ):
            raise PolicyError("Scope must be an exact HTTPS origin on port 443 without credentials")
        if not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host
        ):
            raise PolicyError(
                "A fully qualified DNS hostname is required; IP literals are disabled"
            )
        if host.endswith(
            (".localhost", ".local", ".internal", ".test", ".invalid", ".example", ".onion")
        ):
            raise PolicyError("Special-use hostnames are disabled")
        return cls(host)


def validate_path(path: str) -> str:
    # Exact, canonical owner-declared paths only. No crawling or URL joining.
    if not re.fullmatch(r"/(?:[a-zA-Z0-9_~.-]+/?)*", path) or len(path) > 512:
        raise PolicyError("Use a canonical absolute path without escapes, queries or fragments")
    parts = path.lower().split("/")
    if any(p in (".", "..") for p in parts) or "//" in path:
        raise PolicyError("Ambiguous path")
    if any(
        word in path.lower()
        for word in (
            "logout",
            "delete",
            "remove",
            "purchase",
            "checkout",
            "transfer",
            "reset",
            "unsubscribe",
        )
    ):
        raise PolicyError("Potentially state-changing route is excluded")
    return path

"""Replay a captured HTML response in a disposable, network-blocked Chromium context."""

import asyncio
from html.parser import HTMLParser

from playwright.async_api import async_playwright


class Dependencies(HTMLParser):
    def __init__(self):
        super().__init__()
        self.external = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if (
            tag in ("iframe", "object", "embed", "base")
            or any(key in attrs for key in ("src", "srcset"))
            or (tag == "link" and attrs.get("href"))
        ):
            self.external = True


async def proves_execution(response, url, marker):
    if (
        response.status != 200
        or "text/html" not in response.headers.get("content-type", "").lower()
    ):
        return False
    dependencies = Dependencies()
    dependencies.feed(response.body.decode("utf-8", errors="replace"))
    if dependencies.external:
        return None
    async with asyncio.timeout(15), async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            chromium_sandbox=True,
            args=[
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-extensions",
                "--disable-sync",
                "--disable-quic",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                "--proxy-server=http://127.0.0.1:9",
                "--proxy-bypass-list=<-loopback>",
                "--host-resolver-rules=MAP * ~NOTFOUND",
            ],
        )
        try:
            context = await browser.new_context(service_workers="block", accept_downloads=False)
            await context.route_web_socket("**/*", lambda ws: ws.close())
            page = await context.new_page()

            async def popup(new_page):
                if new_page != page:
                    await new_page.close()

            context.on("page", popup)
            used = False
            blocked = []
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)

            async def route_request(route):
                nonlocal used
                req = route.request
                if (
                    not used
                    and req.is_navigation_request()
                    and req.frame == page.main_frame
                    and req.url == url
                ):
                    used = True
                    headers = {
                        k: v
                        for k, v in response.headers.items()
                        if k
                        in ("content-type", "content-security-policy", "x-content-type-options")
                    }
                    # Additional sandbox CSP limits escape capabilities, preserving original CSP.
                    sandbox = "sandbox allow-scripts; connect-src 'none'; worker-src 'none'; child-src 'none'; object-src 'none'; form-action 'none'; base-uri 'none'"
                    headers["content-security-policy"] = (
                        headers.get("content-security-policy", "")
                        + (", " if headers.get("content-security-policy") else "")
                        + sandbox
                    )
                    await route.fulfill(status=200, headers=headers, body=response.body)
                else:
                    blocked.append(req.url)
                    await route.abort()

            await context.route("**/*", route_request)
            await page.goto(url, wait_until="domcontentloaded", timeout=4000)
            await page.wait_for_timeout(100)
            executed = await page.locator("html").get_attribute("data-racs-proof") == marker
            return None if (blocked or errors) else executed
        finally:
            await browser.close()

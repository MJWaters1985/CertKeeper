"""Captures the web interface screenshots in docs/screenshots from a running demo server.

Run by tools/demo/run.sh inside Microsoft's Playwright image; see there.
"""
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("CERTKEEPER_URL", "https://host.docker.internal:18450")
OUT = sys.argv[1] if len(sys.argv) > 1 else "/out"


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1360, "height": 860}, device_scale_factor=2,
                                ignore_https_errors=True, color_scheme="dark")
        page.goto(BASE + "/")
        page.fill("input[autocomplete=username]", "demo")
        page.fill("input[type=password]", "demo-password-1")
        page.click("button[type=submit]")
        page.wait_for_selector(".layout")
        # A token so the overview doesn't ask for one (the demo never talks to Cloudflare).
        page.evaluate("""fetch('/api/cloudflare', {method: 'PUT', credentials: 'same-origin',
            headers: {'X-CertKeeper': '1', 'Content-Type': 'application/json'}, body: JSON.stringify({token: 'demo'})})""")
        state = page.evaluate("fetch('/api/state').then(r => r.json())")

        def shot(name, hash_, full=False):
            page.goto(BASE + "/" + hash_)
            page.reload()
            page.wait_for_selector(".page h1")
            page.wait_for_timeout(400)
            page.screenshot(path=os.path.join(OUT, name), full_page=full)
            print("captured", name)

        cert = next(c for c in state["certificates"] if c["certificate"]["name"] == "nas.example.com")
        host = next(h for h in state["hosts"] if h["host"]["name"] == "nas.example.com")
        shot("1-overview.png", "#/overview")
        shot("2-certificate.png", f"#/certificate/{cert['certificate']['id']}")
        shot("3-host.png", f"#/host/{host['host']['id']}")
        shot("4-activity.png", "#/activity")

        page.set_viewport_size({"width": 390, "height": 844})
        shot("5-phone.png", "#/overview")
        browser.close()


if __name__ == "__main__":
    main()

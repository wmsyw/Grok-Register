#!/usr/bin/env python3
"""Mint Castle request token via Playwright + CloakBrowser.

Browser frontends send castleRequestToken on email-code + signup. Without it,
x.ai may still return SSO but later OAuth device grants fail with invalid_grant.

Correct Castle v2 usage (not window.Castle):
  - fetch SDK outside the page (avoid CORS)
  - inject with (0, eval)(src) so IIFE runs
  - window._castle('setAppId', pk)
  - window._castle('createRequestToken')

Usage:
  castle_mint.py [--url URL] [--proxy URL] [--chrome PATH] [--pk PK]
                 [--cookie 'a=b; c=d'] [--timeout 60]

Prints only the token to stdout on success.
"""
from __future__ import annotations

import argparse
import asyncio
import glob
import os
import sys
import time
import urllib.request

# Public Castle publishable key observed on accounts.x.ai.
DEFAULT_CASTLE_PK = "pk_p8GGWvD3TmFJZRsX3BQcqAv9aFVispNz"
DEFAULT_URL = "https://accounts.x.ai/sign-up"
CDN_V2 = "https://cdn.castle.io/v2/castle.js"


def cloak_cache_dirs() -> list[str]:
    """Chromium cache roots, most-specific first.

    CLOAKBROWSER_CACHE_DIR wins: a side-by-side install points it at its own
    directory so it never picks up (or races) another install's ~/.cloakbrowser.
    """
    env = (os.environ.get("CLOAKBROWSER_CACHE_DIR") or "").strip()
    if env:
        return [env]
    bases: list[str] = []
    h = os.path.expanduser("~")
    if h:
        bases.append(os.path.join(h, ".cloakbrowser"))
    for home in ("/root", "/home/charles"):
        bases.append(os.path.join(home, ".cloakbrowser"))
    return bases


def find_chrome() -> str:
    env = (os.environ.get("CHROME_PATH") or "").strip()
    if env and os.path.exists(env):
        return env
    matches: list[str] = []
    for base in cloak_cache_dirs():
        matches.extend(glob.glob(os.path.join(base, "chromium-*/chrome")))
        matches.extend(
            glob.glob(
                os.path.join(
                    base,
                    "chromium-*/Chromium.app/Contents/MacOS/Chromium",
                )
            )
        )
    if matches:
        return sorted(matches)[-1]
    for p in (
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ):
        if os.path.exists(p):
            return p
    return ""


def parse_cookie_header(raw: str) -> list[dict]:
    out: list[dict] = []
    for part in (raw or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, val = part.split("=", 1)
        name, val = name.strip(), val.strip()
        if not name or name.lower() in {"sso", "sso-rw"}:
            continue
        out.append(
            {
                "name": name,
                "value": val,
                "domain": ".x.ai",
                "path": "/",
            }
        )
    return out


def has_display() -> bool:
    return bool(
        (os.environ.get("DISPLAY") or "").strip()
        or (os.environ.get("WAYLAND_DISPLAY") or "").strip()
    )


def fetch_castle_sdk(proxy: str) -> str:
    """Download Castle v2 SDK using urllib (supports HTTP proxy)."""
    for local in (
        os.environ.get("CASTLE_JS_PATH", "").strip(),
        "/usr/local/share/xai-reg/castle_v2.js",
        os.path.join(os.path.dirname(__file__), "castle_v2.js"),
    ):
        if local and os.path.isfile(local):
            with open(local, "r", encoding="utf-8", errors="replace") as f:
                data = f.read()
            if len(data) > 100:
                return data

    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers) if handlers else urllib.request.build_opener()
    req = urllib.request.Request(
        CDN_V2,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            ),
            "Accept": "*/*",
        },
    )
    with opener.open(req, timeout=45) as resp:
        data = resp.read().decode("utf-8", "replace")
    if len(data) < 100:
        raise RuntimeError(f"castle sdk too short ({len(data)})")
    return data


async def mint(
    *,
    page_url: str,
    proxy: str,
    chrome: str,
    cookies: list[dict],
    timeout: float,
    ua: str,
    pk: str,
    mode: str,
) -> str:
    from playwright.async_api import async_playwright

    # Fetch SDK outside the page (page fetch is often CORS/proxy blocked).
    sdk_js = fetch_castle_sdk(proxy)

    # Prefer headed offscreen (true headless is weaker / flakier for anti-bot SDKs).
    use_headless = mode == "headless"
    args = [
        "--disable-blink-features=AutomationControlled",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    if not use_headless:
        args.extend(["--window-position=-32000,-32000", "--window-size=900,700"])
    launch: dict = {
        "executable_path": chrome,
        "headless": use_headless,
        "args": args,
    }
    if proxy:
        launch["proxy"] = {"server": proxy}

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(**launch)
        try:
            ctx_kwargs: dict = {"viewport": {"width": 900, "height": 700}}
            if ua:
                ctx_kwargs["user_agent"] = ua
            context = await browser.new_context(**ctx_kwargs)
            if cookies:
                await context.add_cookies(cookies)
            page = await context.new_page()
            await page.goto(page_url, wait_until="domcontentloaded", timeout=int(timeout * 1000))
            await page.wait_for_timeout(500)

            # Inject via (0, eval) so Castle IIFE actually runs.
            await page.evaluate(
                """(code) => {
                    (0, eval)(code);
                    if (typeof window._castle !== 'function') {
                        throw new Error('window._castle missing after eval inject');
                    }
                }""",
                sdk_js,
            )

            deadline = time.time() + timeout
            last_err = ""
            while time.time() < deadline:
                try:
                    tok = await page.evaluate(
                        """async (pk) => {
                            if (typeof window._castle !== 'function') {
                                throw new Error('window._castle missing');
                            }
                            try { window._castle('setAppId', pk); } catch (e) {}
                            let tok = window._castle('createRequestToken');
                            if (tok && typeof tok.then === 'function') tok = await tok;
                            return (typeof tok === 'string') ? tok : '';
                        }""",
                        pk,
                    )
                    if tok and isinstance(tok, str) and len(tok) >= 20:
                        try:
                            cks = await context.cookies()
                            # Prefer CF / castle related cookies for protocol reuse.
                            parts = []
                            for c in cks:
                                n = c.get("name") or ""
                                if n.lower() in {"sso", "sso-rw"}:
                                    continue
                                parts.append(f"{n}={c.get('value','')}")
                            if parts:
                                print("COOKIES: " + "; ".join(parts), file=sys.stderr)
                        except Exception:
                            pass
                        return tok
                    last_err = f"short token len={len(tok) if isinstance(tok, str) else type(tok)}"
                except Exception as exc:
                    last_err = f"{type(exc).__name__}: {exc}"
                await page.wait_for_timeout(600)

            try:
                diag = await page.evaluate(
                    """() => ({
                      has_castle: typeof window._castle,
                      has_Castle: typeof window.Castle,
                      title: document.title || '',
                    })"""
                )
                print(f"diag={diag} last={last_err}", file=sys.stderr)
            except Exception:
                print(f"last={last_err}", file=sys.stderr)
            raise RuntimeError(f"castle timeout ({last_err})")
        finally:
            await browser.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--proxy", default="")
    ap.add_argument("--chrome", default="")
    ap.add_argument("--cookie", default="")
    ap.add_argument("--ua", default="")
    ap.add_argument("--pk", default=os.environ.get("CASTLE_PK", DEFAULT_CASTLE_PK))
    ap.add_argument("--timeout", type=float, default=60)
    ap.add_argument(
        "--mode",
        default="offscreen",
        choices=("offscreen", "headless", "auto"),
    )
    args = ap.parse_args()

    chrome = args.chrome.strip() or find_chrome()
    if not chrome:
        print("chrome not found", file=sys.stderr)
        return 1
    cookies = parse_cookie_header(args.cookie)
    mode = args.mode
    if mode == "auto":
        mode = "offscreen"
    try:
        token = asyncio.run(
            mint(
                page_url=args.url.strip() or DEFAULT_URL,
                proxy=args.proxy.strip(),
                chrome=chrome,
                cookies=cookies,
                timeout=args.timeout,
                ua=args.ua.strip(),
                pk=args.pk.strip() or DEFAULT_CASTLE_PK,
                mode=mode,
            )
        )
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if not token or len(token) < 20:
        print("empty castle token", file=sys.stderr)
        return 1
    sys.stdout.write(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

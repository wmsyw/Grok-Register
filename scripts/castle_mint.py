#!/usr/bin/env python3
"""Mint Castle request token via Playwright + CloakBrowser.

Browser frontends send castleRequestToken on email-code + signup. Without it,
x.ai may still return SSO but later OAuth device grants fail with invalid_grant.

Correct Castle v2 usage (not window.Castle):
  - inject SDK with (0, eval)(src) so IIFE runs
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

# Public Castle publishable key observed on accounts.x.ai (same as grok-build-auth).
DEFAULT_CASTLE_PK = "pk_p8GGWvD3TmFJZRsX3BQcqAv9aFVispNz"
DEFAULT_URL = "https://accounts.x.ai/sign-up"
CDN_V2 = "https://cdn.castle.io/v2/castle.js"


def find_chrome() -> str:
    env = (os.environ.get("CHROME_PATH") or "").strip()
    if env and os.path.exists(env):
        return env
    homes = []
    h = os.path.expanduser("~")
    if h:
        homes.append(h)
    homes.extend(["/root", "/home/charles"])
    matches: list[str] = []
    for home in homes:
        base = os.path.join(home, ".cloakbrowser")
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

    headless = mode == "headless"
    launch: dict = {
        "executable_path": chrome,
        "headless": headless,
        "args": [
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
            "--disable-dev-shm-usage",
        ],
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
            await page.wait_for_timeout(800)

            # Inject Castle v2 correctly: fetch source then (0, eval)(src).
            # Prefer page-local / cached script if present; else CDN.
            inject = f"""
async () => {{
  const PK = {pk!r};
  const CDN = {CDN_V2!r};

  function ready() {{
    return typeof window._castle === 'function';
  }}

  async function loadSDK() {{
    if (ready()) return true;
    // Prefer same-origin cached copy if the app already loaded one.
    let src = '';
    const existing = [...document.querySelectorAll('script[src*="castle"]')];
    for (const s of existing) {{
      if (s.src) {{ src = s.src; break; }}
    }}
    if (!src) {{
      // try common local cache path used by some frontends
      try {{
        const r = await fetch('/data/cf-cache/castle_v2.js', {{credentials:'include'}});
        if (r.ok) src = URL.createObjectURL(await r.blob());
      }} catch (e) {{}}
    }}
    if (!src) src = CDN;

    // If already a classic script tag path works:
    if (src.startsWith('http') || src.startsWith('/')) {{
      await new Promise((resolve, reject) => {{
        const s = document.createElement('script');
        s.src = src.startsWith('http') || src.startsWith('/') ? src : CDN;
        s.async = true;
        s.onload = () => resolve(true);
        s.onerror = () => reject(new Error('castle script load failed'));
        document.head.appendChild(s);
      }}).catch(() => null);
    }}

    if (!ready()) {{
      // Force-eval CDN body so IIFE executes (script.textContent alone often does not).
      const r = await fetch(CDN, {{credentials:'omit', mode:'cors'}});
      if (!r.ok) throw new Error('castle cdn http ' + r.status);
      const code = await r.text();
      (0, eval)(code);
    }}
    if (!ready()) throw new Error('window._castle missing after inject');
    return true;
  }}

  await loadSDK();
  try {{ window._castle('setAppId', PK); }} catch (e) {{}}
  // createRequestToken may be sync or Promise depending on SDK build.
  let tok = window._castle('createRequestToken');
  if (tok && typeof tok.then === 'function') tok = await tok;
  if (!tok || typeof tok !== 'string' || tok.length < 20) {{
    // retry once after short wait
    await new Promise(r => setTimeout(r, 500));
    tok = window._castle('createRequestToken');
    if (tok && typeof tok.then === 'function') tok = await tok;
  }}
  return tok || '';
}}
"""
            deadline = time.time() + timeout
            last_err = ""
            while time.time() < deadline:
                try:
                    tok = await page.evaluate(inject)
                    if tok and isinstance(tok, str) and len(tok) >= 20:
                        return tok
                    last_err = f"short token len={len(tok) if isinstance(tok, str) else type(tok)}"
                except Exception as exc:
                    last_err = f"{type(exc).__name__}: {exc}"
                await page.wait_for_timeout(700)

            # diagnostics
            try:
                diag = await page.evaluate(
                    """() => ({
                      has_castle: typeof window._castle,
                      has_Castle: typeof window.Castle,
                      scripts: [...document.querySelectorAll('script[src]')].map(s=>s.src).filter(s=>/castle/i.test(s)).slice(0,5),
                      title: document.title||'',
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
        mode = "offscreen" if has_display() or True else "headless"
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

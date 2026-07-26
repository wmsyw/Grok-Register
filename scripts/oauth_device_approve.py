#!/usr/bin/env python3
"""Authorize an xAI OAuth device code through the live consent UI.

The SSO token is read from stdin so it never appears in argv or diagnostics.
Prints only ``ok`` on success; sanitized diagnostics go to stderr.
"""
from __future__ import annotations

import argparse
import asyncio
import glob
import os
import re
import sys
import time


SUCCESS_PATH = "/oauth2/device/done"
POSITIVE_BUTTON = re.compile(r"(?:continue|allow|authorize|approve|继续|允许|授权|确认)", re.I)
NEGATIVE_BUTTON = re.compile(r"(?:deny|decline|cancel|reject|拒绝|取消)", re.I)
SIGN_IN_TEXT = re.compile(r"(?:sign[ -]?in|log[ -]?in|登录)", re.I)
SUCCESS_TEXT = re.compile(r"(?:device (?:is )?authorized|you have authorized|设备已授权|授权成功)", re.I)


def find_chrome() -> str:
    override = (os.environ.get("CLOAKBROWSER_BINARY_PATH") or os.environ.get("CHROME_PATH") or "").strip()
    if override and os.path.isfile(override):
        return override
    roots = [
        (os.environ.get("CLOAKBROWSER_CACHE_DIR") or "").strip(),
        "/root/.xai/cloakbrowser",
        os.path.join(os.path.expanduser("~"), ".cloakbrowser"),
    ]
    matches: list[str] = []
    for root in roots:
        if not root:
            continue
        matches.extend(glob.glob(os.path.join(root, "chromium-*/chrome")))
        matches.extend(glob.glob(os.path.join(root, "chromium-*/Chromium.app/Contents/MacOS/Chromium")))
    if matches:
        return sorted(matches)[-1]
    for path in ("/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium", "/usr/bin/chromium-browser"):
        if os.path.isfile(path):
            return path
    return ""


def has_display() -> bool:
    return bool((os.environ.get("DISPLAY") or "").strip() or (os.environ.get("WAYLAND_DISPLAY") or "").strip())


async def set_allow_action(page) -> None:
    await page.evaluate(
        """() => {
            for (const input of document.querySelectorAll('input[name="action"]')) {
                input.value = 'allow';
                input.setAttribute('value', 'allow');
                input.dispatchEvent(new Event('input', {bubbles: true}));
                input.dispatchEvent(new Event('change', {bubbles: true}));
            }
        }"""
    )


async def dismiss_cookie_overlay(page) -> None:
    for selector in (
        "#onetrust-accept-btn-handler",
        "#onetrust-reject-all-handler",
        ".onetrust-close-btn-handler",
    ):
        button = page.locator(selector)
        try:
            if await button.count() > 0 and await button.first.is_visible():
                await button.first.click(force=True, timeout=3000)
                await page.wait_for_timeout(150)
                return
        except Exception:
            continue
    try:
        await page.evaluate(
            """() => {
                for (const selector of ['#onetrust-consent-sdk', '#onetrust-banner-sdk', '.onetrust-pc-dark-filter']) {
                    document.querySelector(selector)?.remove();
                }
                document.documentElement.style.overflow = 'auto';
                document.body.style.overflow = 'auto';
            }"""
        )
    except Exception:
        pass


async def click_positive_button(page) -> bool:
    buttons = page.get_by_role("button")
    count = await buttons.count()
    for index in range(count):
        button = buttons.nth(index)
        try:
            if not await button.is_visible() or not await button.is_enabled():
                continue
            label = " ".join((await button.inner_text()).split())
            if NEGATIVE_BUTTON.search(label) or not POSITIVE_BUTTON.search(label):
                continue
            await set_allow_action(page)
            await button.click(force=True, timeout=8000)
            return True
        except Exception:
            continue
    submits = page.locator('button[type="submit"], input[type="submit"]')
    count = await submits.count()
    for index in range(count):
        submit = submits.nth(index)
        try:
            if not await submit.is_visible() or not await submit.is_enabled():
                continue
            label = " ".join(((await submit.get_attribute("value")) or (await submit.inner_text()) or "").split())
            if NEGATIVE_BUTTON.search(label):
                continue
            await set_allow_action(page)
            await submit.click(force=True, timeout=8000)
            return True
        except Exception:
            continue
    return False


async def approve(*, url: str, sso: str, proxy: str, chrome: str, timeout: float, ua: str) -> None:
    from playwright.async_api import async_playwright

    launch = {
        "executable_path": chrome,
        "headless": not has_display(),
        "args": [
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-blink-features=AutomationControlled",
            "--no-first-run",
            "--no-default-browser-check",
            "--window-position=-32000,-32000",
            "--window-size=900,700",
        ],
    }
    if proxy:
        launch["proxy"] = {"server": proxy}

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(**launch)
        try:
            context_args = {"viewport": {"width": 900, "height": 700}}
            if ua:
                context_args["user_agent"] = ua
            context = await browser.new_context(**context_args)
            await context.add_init_script('Object.defineProperty(navigator,"webdriver",{get:()=>undefined})')
            await context.add_cookies([
                {"name": "sso", "value": sso, "domain": ".x.ai", "path": "/", "secure": True, "sameSite": "Lax"}
            ])
            page = await context.new_page()
            await page.goto(url, wait_until="domcontentloaded", timeout=min(45000, int(timeout * 1000)))

            deadline = time.monotonic() + timeout
            last_url = page.url
            while time.monotonic() < deadline:
                last_url = page.url
                if SUCCESS_PATH in last_url:
                    return
                body = ""
                try:
                    body = await page.locator("body").inner_text(timeout=3000)
                except Exception:
                    pass
                if SUCCESS_TEXT.search(body):
                    return
                if ("/sign-in" in last_url or "/login" in last_url) and SIGN_IN_TEXT.search(body):
                    raise RuntimeError("SSO session was redirected to sign-in")

                await dismiss_cookie_overlay(page)
                clicked = await click_positive_button(page)
                await page.wait_for_timeout(800 if clicked else 400)

            raise RuntimeError(f"consent timed out at {last_url[:160]}")
        finally:
            await browser.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--proxy", default="")
    parser.add_argument("--chrome", default="")
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--ua", default="")
    args = parser.parse_args()

    sso = sys.stdin.readline().strip()
    if not sso:
        print("missing SSO on stdin", file=sys.stderr)
        return 2
    chrome = args.chrome.strip() or find_chrome()
    if not chrome:
        print("CloakBrowser Chromium not found", file=sys.stderr)
        return 2
    try:
        asyncio.run(approve(url=args.url, sso=sso, proxy=args.proxy.strip(), chrome=chrome, timeout=max(10, args.timeout), ua=args.ua.strip()))
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

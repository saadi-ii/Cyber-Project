import subprocess, sys, time, socket, shutil, os
from pathlib import Path
from playwright.sync_api import sync_playwright

"""Optional browser test (needs: pip install playwright && playwright install chromium).

Usage (from the project folder, after python gen_keys.py):
    python tests/browser_check.py .

It copies the project to a temporary folder, so credentials.txt is not changed.
"""
import tempfile
SRC = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(".").resolve()
_tmp = Path(tempfile.mkdtemp(prefix="sc_browser_"))
RUN = _tmp / "run"
shutil.copytree(SRC, RUN, ignore=shutil.ignore_patterns("__pycache__", "tests"))
(RUN / "credentials.txt").write_text("{}")

def wait_port(port, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.2)
    return False

def start(cwd):
    srv = subprocess.Popen([sys.executable, "server.py"], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert wait_port(8080), "server did not start"
    ui = subprocess.Popen([sys.executable, "client_ui.py"], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert wait_port(8000), "bridge did not start"
    return srv, ui

def stop(*procs):
    for p in procs:
        p.terminate()
        try: p.wait(timeout=10)
        except Exception: p.kill()

results = {}
srv, ui = start(RUN)
try:
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        errors = []
        ctx_a = browser.new_context(); pa = ctx_a.new_page()
        pa.on("pageerror", lambda e: errors.append(str(e)))
        ctx_b = browser.new_context(); pb = ctx_b.new_page()
        pb.on("pageerror", lambda e: errors.append(str(e)))
        pa.goto("http://127.0.0.1:8000/"); pb.goto("http://127.0.0.1:8000/")

        def register(page, name, pw_):
            page.click('.tab[data-mode="register"]')
            page.fill("#username", name); page.fill("#password", pw_)
            page.click("#auth-submit")
            page.wait_for_selector("#app:not([hidden])", timeout=20000)

        register(pa, "alice", "Pw-alice-1")
        register(pb, "bob", "Pw-bob-1")
        results["both_registered_via_signed_gcm_handshake"] = True

        pa.wait_for_selector('#contacts .contact:has-text("bob")', timeout=15000)
        pa.click('#contacts .contact:has-text("bob")')
        pa.fill("#message-input", "hello bob, this is encrypted")
        pa.click("#send-btn")
        pb.wait_for_selector('#contacts .contact:has-text("alice")', timeout=15000)
        pb.click('#contacts .contact:has-text("alice")')
        pb.wait_for_selector('.bubble:has-text("hello bob, this is encrypted")', timeout=15000)
        results["message_delivered_to_bob"] = True
        pa.wait_for_selector(".ticks", timeout=15000)
        results["sender_ticks_shown"] = True
        results["page_errors"] = errors
        browser.close()
finally:
    stop(srv, ui)

# Negative check: bridge with a key that does not match the pinned key must be refused.
neg = _tmp / "neg"
if neg.exists(): shutil.rmtree(neg)
shutil.copytree(RUN, neg)
import subprocess as sp
sp.run([sys.executable, "-c", "from Crypto.PublicKey import RSA; open('keys/ui_private.pem','wb').write(RSA.generate(3072).export_key())"], cwd=neg, check=True)
srv2, ui2 = start(neg)
try:
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_context().new_page()
        page.goto("http://127.0.0.1:8000/")
        page.click('.tab[data-mode="register"]')
        page.fill("#username", "mallory"); page.fill("#password", "Pw-mallory-1")
        page.click("#auth-submit")
        time.sleep(4)
        text = page.inner_text("#auth-error") if page.query_selector("#auth-error") else ""
        results["mismatched_bridge_key_refused"] = ("verify" in text.lower()) or ("could not" in text.lower()) or ("refused" in text.lower())
        results["mismatched_bridge_message"] = text.strip()
        results["mismatched_app_visible"] = page.is_visible("#app")
        browser.close()
finally:
    stop(srv2, ui2)

for k, v in results.items():
    print(f"{k}: {v}")
shutil.rmtree(_tmp, ignore_errors=True)

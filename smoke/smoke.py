"""End-to-end smoke test for the local compose stack (everything on 127.0.0.1).

    cd Projects && docker compose up -d --build     # stack up and healthy
    python infra/smoke/smoke.py                      # exit 0 = all checks passed

What it covers: health of every service; the security regressions that matter (unsigned
writes refused, a header signed with the retired public HMAC default refused and one signed
with the real secret accepted, actuator surface, anonymous writes bounced to /login,
open-redirect targets, form limits); the UI pages and pager; and one real flow through
UI -> BFF -> catalogues -> User (register, create an ingredient with a brand-new tag,
create a recipe, composed recipe page, the three calculators, the >=1-ingredient rule).

Test credentials are generated at run time and never printed. It cleans up after itself
except for what the UI can't delete: a `zzsmoke...` account and a `zz-smoke-...` tag in
RecipeCatalogue (both clearly named).
"""
import hashlib
import hmac
import os
import re
import secrets
import sys
import time

import requests

UI = "http://localhost:8081"
BFF = "http://localhost:8080"
IC = "http://localhost:8082"
RC = "http://localhost:8083"
USER = "http://localhost:8084"
CRAWLER = "http://localhost:8086"
TIMEOUT = 30

passed, failed = [], []


def check(name, ok, detail=""):
    (passed if ok else failed).append(name)
    print(("PASS  " if ok else "FAIL  ") + name + (f"   [{detail}]" if detail and not ok else ""))
    return ok


def get(url, **kw):
    return requests.get(url, timeout=TIMEOUT, allow_redirects=kw.pop("allow_redirects", True), **kw)


def csrf_from(html):
    m = re.search(r'name="_csrf"\s+value="([^"]+)"', html) or re.search(r'value="([^"]+)"\s+name="_csrf"', html)
    return m.group(1) if m else None


def stack_secret():
    """The stack's INTERNAL_AUTH_SECRET, read from Projects/.env (never printed)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".env")
    for line in open(path, encoding="utf-8"):
        if line.startswith("INTERNAL_AUTH_SECRET="):
            return line.strip().split("=", 1)[1]
    return None


def sign(secret, method, path, acting_user=None):
    """An X-Internal-Auth value, built the same way as InternalAuth.header."""
    t = int(time.time() * 1000)
    u = "-" if acting_user is None else str(acting_user)
    mac = hmac.new(secret.encode(), f"{method.upper()}\n{path}\n{u}\n{t}".encode(), hashlib.sha256)
    return f"t={t},u={u},s={mac.hexdigest()}"


stamp = str(int(time.time()))
tag = f"zz-smoke-{stamp}"
ing_name = f"zz-smoke-ingredient-{stamp}"
rec_name = f"zz-smoke-recipe-{stamp}"

print("== 1. health ==")
for label, url in [
    ("bff", f"{BFF}/actuator/health"), ("ingredient-catalogue", f"{IC}/actuator/health"),
    ("recipe-catalogue", f"{RC}/actuator/health"), ("user", f"{USER}/actuator/health"),
    ("ui", f"{UI}/actuator/health"), ("recipe-crawler", f"{CRAWLER}/actuator/health"),
]:
    try:
        r = get(url)
        check(f"health {label}", r.status_code == 200 and '"UP"' in r.text, f"{r.status_code} {r.text[:60]}")
    except Exception as e:  # noqa: BLE001
        check(f"health {label}", False, str(e)[:80])
for label, url in [("zipkin", "http://localhost:9411/health"), ("prometheus", "http://localhost:9412/-/ready"),
                   ("grafana", "http://localhost:3000/api/health")]:
    try:
        r = get(url)
        check(f"health {label}", r.status_code == 200, str(r.status_code))
    except Exception as e:  # noqa: BLE001
        check(f"health {label}", False, str(e)[:80])

print("== 2. security regression spot-checks ==")
r = requests.post(f"{IC}/api/ingredients", json={"name": f"zz-unsigned-{stamp}"}, timeout=TIMEOUT)
check("C2 unsigned write to IngredientCatalogue is rejected", r.status_code == 403, str(r.status_code))
r = requests.post(f"{RC}/api/recipes", json={"name": f"zz-unsigned-{stamp}"}, timeout=TIMEOUT)
check("C2 unsigned write to RecipeCatalogue is rejected", r.status_code == 403, str(r.status_code))
r = get(f"{USER}/api/restrictions")
check("C1 unsigned read on User /api/** is rejected", r.status_code in (401, 403), str(r.status_code))
r = get(f"{IC}/api/ingredients?sort=(select 1)")
check("M6 bad ?sort= is 400, not 500", r.status_code == 400, str(r.status_code))
r = get(f"{UI}/")
h = r.headers
check("UI security headers (frame/nosniff/CSP/referrer)",
      h.get("X-Frame-Options", "").upper() == "DENY" and h.get("X-Content-Type-Options", "").lower() == "nosniff"
      and bool(h.get("Content-Security-Policy")) and h.get("Referrer-Policy") == "no-referrer", str(dict(h))[:120])

print("== 2b. N5 actuator surface + N7 anonymous writes ==")
for path in ("/actuator/caches", "/actuator/metrics"):
    r = requests.get(BFF + path, timeout=TIMEOUT)
    check(f"N5 BFF {path} is not exposed", r.status_code == 404, str(r.status_code))
r = requests.delete(BFF + "/actuator/caches", timeout=TIMEOUT)
check("N5 BFF DELETE /actuator/caches is not exposed", r.status_code == 404, str(r.status_code))
r = requests.get(BFF + "/actuator/prometheus", timeout=TIMEOUT)
check("N5 BFF prometheus still scrapes (incl. cache stats)", r.status_code == 200 and "cache_gets_total" in r.text,
      str(r.status_code))

anon = requests.Session()   # never logged in
page = anon.get(f"{UI}/tags", timeout=TIMEOUT)
atok = csrf_from(page.text)
for method, path, data in [
        ("POST", "/ingredients", {"name": "zz-anon", "tags": ""}),
        ("POST", "/recipes", {"name": "zz-anon"}),
        ("POST", "/tags", {"name": "zz-anon"}),
        ("POST", "/tags/merge", {"from": "a", "into": "b"}),
        ("POST", "/nutrition-reference", {"name": "zz-anon"}),
        ("POST", "/recipes/import-url/preview", {"url": "http://example.invalid/"}),
        ("POST", "/recipes/crawl", {"seeds": "http://example.invalid/"}),
        ("GET", "/ingredients/new", None), ("GET", "/recipes/new", None), ("GET", "/import", None),
        ("GET", "/recipes/import-url", None), ("GET", "/recipes/crawl", None)]:
    if method == "POST":
        r = anon.post(UI + path, data={**data, "_csrf": atok}, allow_redirects=False, timeout=TIMEOUT)
    else:
        r = anon.get(UI + path, allow_redirects=False, timeout=TIMEOUT)
    loc = r.headers.get("Location", "")
    check(f"N7 anonymous {method} {path} is sent to /login", r.status_code in (302, 303) and "/login" in loc,
          f"{r.status_code} {loc[:60]}")
tok = csrf_from(anon.get(f"{UI}/login", timeout=TIMEOUT).text)
r = anon.post(f"{UI}/settings/theme", data={"theme": "matcha", "_csrf": tok}, allow_redirects=False, timeout=TIMEOUT)
check("the theme switch still works without a login", r.status_code in (302, 303)
      and "/login" not in r.headers.get("Location", ""), f"{r.status_code} {r.headers.get('Location', '')}")

print("== 2c. N1 the HMAC secret: the retired public default is worthless, the real one works ==")
RETIRED_DEFAULT = "dev-internal-secret-change-me"   # was published in the repos; must open nothing now
real = stack_secret()
check("N1 the stack runs with a random secret (>= 32 chars, not the retired default)",
      bool(real) and len(real) >= 32 and real != RETIRED_DEFAULT)
PROBES = [   # each is harmless if accepted: a missing id, a read, or an invalid body
    ("IngredientCatalogue", "DELETE", IC, "/api/ingredients/999999999", None),
    ("RecipeCatalogue", "DELETE", RC, "/api/recipes/999999999", None),
    ("User", "GET", USER, "/api/restrictions", None),
    ("recipe-crawler", "POST", CRAWLER, "/api/import/preview", {"url": ""}),
]
for label, method, base, path, body in PROBES:
    r = requests.request(method, base + path, json=body, timeout=TIMEOUT,
                         headers={"X-Internal-Auth": sign(RETIRED_DEFAULT, method, path)})
    check(f"N1 {label} refuses a header signed with the retired public default", r.status_code == 403,
          str(r.status_code))
    if real:
        r = requests.request(method, base + path, json=body, timeout=TIMEOUT,
                             headers={"X-Internal-Auth": sign(real, method, path)})
        check(f"N1 {label} accepts a header signed with the stack's real secret (anything but 403)",
              r.status_code != 403, str(r.status_code))

print("== 3. UI pages + pager ==")
for path in ["/", "/ingredients", "/recipes", "/tags", "/nutrition-reference", "/login", "/register"]:
    r = get(UI + path)
    check(f"GET {path}", r.status_code == 200, str(r.status_code))
r = get(f"{UI}/nutrition-reference?jump=2")
check("nutrition-reference pager jump=2 renders page 2", r.status_code == 200 and re.search(r"of\s*2", r.text) is not None,
      str(r.status_code))
r = get(f"{UI}/ingredients?jump=1")
check("ingredients pager jump=1", r.status_code == 200, str(r.status_code))

print("== 4. end-to-end flow through UI -> BFF -> services ==")
s = requests.Session()
username = f"zzsmoke{stamp}"
password = secrets.token_urlsafe(18)  # throwaway local test credential, never printed

page = s.get(f"{UI}/register", timeout=TIMEOUT)
token = csrf_from(page.text)
check("register form has a CSRF token", token is not None)
set_cookie = page.headers.get("Set-Cookie", "")
check("session cookie is HttpOnly + SameSite=Strict", "JSESSIONID" in set_cookie and "HttpOnly" in set_cookie
      and "SameSite=Strict" in set_cookie, set_cookie[:120])
r = s.post(f"{UI}/register", data={"username": username, "email": f"{username}@example.invalid",
                                   "displayName": "Smoke Test", "password": password, "_csrf": token},
           allow_redirects=False, timeout=TIMEOUT)
check("register succeeds (redirect)", r.status_code in (302, 303), f"{r.status_code}")

# make sure we are logged in (register may or may not log in)
acct = s.get(f"{UI}/account", allow_redirects=False, timeout=TIMEOUT)
if acct.status_code in (302, 303):
    page = s.get(f"{UI}/login", timeout=TIMEOUT)
    token = csrf_from(page.text)
    r = s.post(f"{UI}/login", data={"identifier": username, "password": password, "_csrf": token},
               allow_redirects=False, timeout=TIMEOUT)
    check("login succeeds (redirect)", r.status_code in (302, 303), f"{r.status_code}")
    acct = s.get(f"{UI}/account", allow_redirects=False, timeout=TIMEOUT)
check("logged-in /account is reachable", acct.status_code == 200, str(acct.status_code))


# --- N3: the login redirect target can never leave the site ---
def login_with_next(nxt):
    s2 = requests.Session()
    t = csrf_from(s2.get(f"{UI}/login", timeout=TIMEOUT).text)
    return s2.post(f"{UI}/login", data={"identifier": username, "password": password, "next": nxt, "_csrf": t},
                   allow_redirects=False, timeout=TIMEOUT)


for evil in ("//evil.example/", "/\\evil.example", "https://evil.example/"):
    r = login_with_next(evil)
    loc = r.headers.get("Location", "")
    on_site = "evil" not in loc and (loc == "/" or loc.rstrip("/").endswith(":8081"))
    check(f"N3 login with next={evil!r} stays on this site", r.status_code in (302, 303) and on_site,
          f"{r.status_code} {loc}")
r = login_with_next("/recipes?name=x")
check("N3 a genuine local next is still honoured", r.headers.get("Location", "").endswith("/recipes?name=x"),
      r.headers.get("Location", ""))

# --- N4 (UI side): an oversized form is refused before any lookup ---
page = s.get(f"{UI}/recipes/new", timeout=TIMEOUT)
big = [("name", "zz-too-big"), ("tags", ""), ("stepText", "x"), ("stepTools", "")]
for i in range(101):
    big += [("lineIngredientName", f"zz-none-{i}"), ("lineReplacementNames", "")]
r = s.post(f"{UI}/recipes", data=big + [("_csrf", csrf_from(page.text))], allow_redirects=False, timeout=TIMEOUT)
check("N4 a 101-line recipe form is refused with a clear message",
      r.status_code == 200 and "at most 100 ingredient lines" in r.text, f"{r.status_code}")
many_tags = ",".join(f"zz-t{i}" for i in range(51))
page = s.get(f"{UI}/ingredients/new", timeout=TIMEOUT)
r = s.post(f"{UI}/ingredients", data={"name": f"zz-tags-{stamp}", "tags": many_tags, "densityGPerMl": "",
                                      "_csrf": csrf_from(page.text)}, allow_redirects=False, timeout=TIMEOUT)
check("N4 an ingredient with 51 tags is not created (IngredientCatalogue answers 400)",
      not (r.status_code in (302, 303) and re.search(r"/ingredients/\d+", r.headers.get("Location", ""))),
      f"{r.status_code} {r.headers.get('Location', '')}")
chk = get(f"{IC}/api/ingredients?name=zz-tags-{stamp}")
check("N4 ...and nothing was stored", chk.status_code == 200 and f"zz-tags-{stamp}" not in chk.text, chk.text[:80])

# --- ingredient with a brand-new tag (get-or-create) ---
page = s.get(f"{UI}/ingredients/new", timeout=TIMEOUT)
token = csrf_from(page.text)
r = s.post(f"{UI}/ingredients", data={"name": ing_name, "tags": tag, "densityGPerMl": "", "_csrf": token},
           allow_redirects=False, timeout=TIMEOUT)
loc = r.headers.get("Location", "")
m = re.search(r"/ingredients/(\d+)", loc)
check("create ingredient (with a novel tag) -> redirect to its page", r.status_code in (302, 303) and m is not None,
      f"{r.status_code} {loc}")
ing_id = m.group(1) if m else None

if ing_id:
    r = s.get(f"{UI}/ingredients/{ing_id}", timeout=TIMEOUT)
    check("ingredient page shows the new tag (tag was get-or-created)", r.status_code == 200 and tag in r.text,
          str(r.status_code))
    r = get(f"{IC}/api/tags?prefix={tag}")
    check("the new tag now exists in IngredientCatalogue", r.status_code == 200 and tag in r.text, str(r.status_code))

# --- recipe rule: >= 1 ingredient ---
page = s.get(f"{UI}/recipes/new", timeout=TIMEOUT)
token = csrf_from(page.text)
r = s.post(f"{UI}/recipes", data=[("name", rec_name), ("creator", ""), ("version", ""), ("tags", tag),
                                  ("stepText", "Mix it."), ("stepTools", ""),
                                  ("lineIngredientName", ""), ("lineAmount", ""), ("lineUnit", ""),
                                  ("lineQuantity", ""), ("lineReplacementNames", ""), ("_csrf", token)],
           allow_redirects=False, timeout=TIMEOUT)
check("recipe with NO ingredient is refused (form re-renders with the message)",
      r.status_code == 200 and "at least one ingredient" in r.text, f"{r.status_code}")

# --- recipe with the ingredient ---
rec_id = None
if ing_id:
    page = s.get(f"{UI}/recipes/new", timeout=TIMEOUT)
    token = csrf_from(page.text)
    r = s.post(f"{UI}/recipes", data=[("name", rec_name), ("creator", ""), ("version", ""), ("tags", tag),
                                      ("stepText", "Mix it."), ("stepTools", ""),
                                      ("lineIngredientName", ing_name), ("lineAmount", "100"), ("lineUnit", "g"),
                                      ("lineQuantity", "100 g"), ("lineReplacementNames", ""), ("_csrf", token)],
               allow_redirects=False, timeout=TIMEOUT)
    loc = r.headers.get("Location", "")
    m = re.search(r"/recipes/(\d+)", loc)
    check("create recipe with 1 ingredient -> redirect to its page", r.status_code in (302, 303) and m is not None,
          f"{r.status_code} {loc}")
    rec_id = m.group(1) if m else None

if rec_id:
    r = s.get(f"{UI}/recipes/{rec_id}", timeout=TIMEOUT)
    check("composed recipe page renders (UI -> BFF -> RC + IC) with the ingredient name",
          r.status_code == 200 and ing_name in r.text, str(r.status_code))
    for path in (f"/recipes/{rec_id}/nutrition?servings=2", f"/recipes/{rec_id}/calories?servings=2",
                 f"/recipes/{rec_id}/portions"):
        r = s.get(UI + path, timeout=TIMEOUT)
        check(f"calculator {path.split('/')[-1].split('?')[0]} renders via the BFF session relay",
              r.status_code == 200, str(r.status_code))
    r = s.get(f"{UI}/recipes?name={rec_name}", timeout=TIMEOUT)
    check("recipe list finds it by name", r.status_code == 200 and rec_name in r.text, str(r.status_code))

print("== 5. cleanup (recipe, ingredient, tag; the account + 1 RecipeCatalogue tag remain) ==")
if rec_id:
    page = s.get(f"{UI}/recipes/{rec_id}", timeout=TIMEOUT)
    r = s.post(f"{UI}/recipes/{rec_id}/delete", data={"_csrf": csrf_from(page.text)}, allow_redirects=False,
               timeout=TIMEOUT)
    check("delete the smoke recipe", r.status_code in (302, 303), str(r.status_code))
if ing_id:
    page = s.get(f"{UI}/ingredients/{ing_id}", timeout=TIMEOUT)
    r = s.post(f"{UI}/ingredients/{ing_id}/delete", data={"_csrf": csrf_from(page.text)}, allow_redirects=False,
               timeout=TIMEOUT)
    check("delete the smoke ingredient", r.status_code in (302, 303), str(r.status_code))

# the IngredientCatalogue tag this run created (writes need a login, so use the logged-in session);
# the RecipeCatalogue tag and the account have no UI delete and are left behind, clearly named zz-smoke*
page = s.get(f"{UI}/tags", params={"prefix": tag}, timeout=TIMEOUT)
for row in re.findall(r"<tr[^>]*>(.*?)</tr>", page.text, flags=re.S):
    m = re.search(r'action="(/tags/\d+/delete)"', row)
    if m and tag in row:
        r = s.post(UI + m.group(1), data={"_csrf": csrf_from(page.text)}, allow_redirects=False, timeout=TIMEOUT)
        check("delete the smoke tag from IngredientCatalogue", r.status_code in (302, 303), str(r.status_code))

print()
print(f"RESULT: {len(passed)} passed, {len(failed)} failed")
if failed:
    print("FAILED: " + "; ".join(failed))
sys.exit(1 if failed else 0)

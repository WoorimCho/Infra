# Allergen Information System — infrastructure

The operational layer for the Allergen Information System: monitoring configuration,
database bootstrap, a reusable CI workflow, and the end-to-end smoke suite that checks the
whole stack before a release.

```
ci/           a reusable GitHub Actions workflow for the Gradle services
grafana/      dashboard JSON and the provisioning that loads it
mysql-init/   one MySQL instance, one schema per service
prometheus/   scrape configuration for the services that expose /actuator/prometheus
smoke/        end-to-end smoke suite (see below)
```

## This directory is not a runnable stack

The stack is brought up by a `compose.yaml` that sits **one level above** this directory and
builds each service from its own repository, cloned as a sibling:

```
Projects/
├─ compose.yaml          brings everything up; mounts ./infra/* read-only
├─ .env                  MySQL passwords + INTERNAL_AUTH_SECRET (never committed)
├─ infra/                this repository
├─ Allergen-Information-System/   the gateway / BFF
├─ IngredientCatalogue/
├─ RecipeCatalogue/
├─ User/
├─ UI/
├─ recipe-crawler/
└─ catalogue-common/     shared library
```

## smoke/smoke.py

An end-to-end check across the running stack, driven over HTTP exactly as a browser and the
services themselves would. Run by hand before a release.

```bash
cd Projects
docker compose up -d --build     # stack up and healthy
python infra/smoke/smoke.py      # exit 0 = every check passed
```

Needs `requests`. It prints a line per check and a `RESULT: n passed, n failed` summary, and
exits non-zero if anything failed, so it can be wired into a pipeline later.

### What it covers

| Section | What it proves |
|---|---|
| **1. Health** | every service answers its health endpoint |
| **2. Security regressions** | unsigned inter-service writes are refused; the actuator surface is what it should be; anonymous writes bounce to `/login`; open-redirect targets are rejected; form limits hold |
| **2c. The HMAC secret** | a header signed with the **retired public default** is refused, and one signed with the real secret is accepted — the check that N1 stayed fixed |
| **3. UI** | pages render and the pager works |
| **4. One real flow** | register → create an ingredient with a brand-new tag → create a recipe → composed recipe page → the three calculators → the one-ingredient-minimum rule, through UI → BFF → catalogues → User |
| **5. Cleanup** | removes the recipe, ingredient and tag it created |

Unit and integration tests live in each service's own repository and run inside one service
each. This suite exists for the failures that only appear **between** services: a malformed
request from the gateway, a header signed the wrong way, a session that does not survive a
hop.

### Notes

- **Test credentials are generated at run time and never printed.**
- The shared `INTERNAL_AUTH_SECRET` is read from the stack's `.env`, which is git-ignored and
  has no default anywhere in the system — a missing value stops the services at startup
  rather than falling back to a published string.
- Cleanup leaves two clearly named artefacts the UI cannot delete: a `zzsmoke…` account and a
  `zz-smoke-…` tag in RecipeCatalogue.

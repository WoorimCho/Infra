# CI

The services live in **separate git repos** — each of IngredientCatalogue,
RecipeCatalogue, User, Allergen-Information-System, UI, recipe-crawler,
GoodNightWorld and catalogue-common has its own `.git`. GitHub Actions runs per
repo, so there is one workflow per repo — not one pipeline that builds all of them.

## In place

Every repo carries `.github/workflows/ci.yml`:

- **Maven service + image** — `Allergen-Information-System`, `UI`,
  `recipe-crawler`: `mvnw -B test` on push/PR; build + push
  `ghcr.io/<repo>` (SHA + `latest`) on push to `main`.
- **Gradle service + image** — `IngredientCatalogue`, `RecipeCatalogue`,
  `User`: `./gradlew test` then the same image push. From
  `gradle-service-ci.yml` in this directory (the reference copy).
- **Maven, test only** — `GoodNightWorld` (frozen demo; image still builds via
  the same job).
- **Gradle library, build only** — `catalogue-common`: `./gradlew build`, no
  image (nothing runs it standalone; the catalogues pull it in via a composite
  build).

## Left to do (needs GitHub, not doable locally)

1. ~~Push each repo to GitHub.~~ Done (2026-09-09) — all 8 under `WoorimCho/`.
2. In each repo: Settings → Actions → Workflow permissions → allow
   **Read and write** (the `ghcr.io` push uses the built-in `GITHUB_TOKEN`; no
   extra secret, but package writes are off by default). `catalogue-common`
   needs only read.
3. First push to `main`/`master` triggers `test` + `image`; PRs trigger `test`.

## Prerequisite decision (single pipeline)

A single pipeline (one PR builds only the services it touched, shared caching,
one place to see status) needs the code in **one repo** — either merge the
services into a monorepo, or add them as submodules of `Projects/`. Until then
it's N independent workflows. See TODO.txt Phase 3 "naming / structure cleanup".

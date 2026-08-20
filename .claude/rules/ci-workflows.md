---
paths:
  - ".github/**"
  - "turbo.json"
  - "infra/docker/**"
  - "docker-compose.stack.yml"
description: CI, workflow, build-input and container rules
---

# CI, workflows and builds

- **Derive container/job/migration lists from the project**, never hand-list them.
  This drift class has bitten four times (stack.yml's migrate list, web.Dockerfile's
  asserted-absent `public/`, images.yml's diagnostics containers, extension.yml's
  paths filter).
- **A fence per layer is not a fence on the chain.** Where a build value crosses N
  boundaries (compose arg → turbo `env` → Dockerfile `ARG` → code), N green fences
  prove nothing. Read the value back out of the ARTIFACT, using a probe value that
  could not have arrived by accident (`*.probe.invalid`).
- Turbo 2 runs builds in STRICT env mode: a variable not declared in the task's `env`
  is STRIPPED, the build exits 0, and the artifact silently carries a default.
  Declare every build-time input. `packages/config/test/workflow-inputs.spec.ts` and
  `apps/web/src/lib/build-inputs.test.ts` enforce this.
- Declare every output in `turbo.json`. An undeclared output is not merely uncached —
  it is ABSENT after a cache hit, and turbo reports the package as built.
- **No prose inside `node -e '…'`.** An apostrophe closes the shell string; at even
  parity it re-balances and the assertion silently never runs. Put logic in
  `.github/scripts/*.mjs` and prose in YAML `#` comments.
- Main-module guards resolve BOTH sides (`pathToFileURL(realpathSync(argv[1])).href`) —
  `import.meta.url` is the real path, `argv[1]` is the path as typed, and a symlink
  makes them differ silently, so `main` never runs and the script exits 0.
- A gate must be invocable: keep `workflow_dispatch` on blocking workflows. Dispatching
  on a ref with a live run in the same concurrency group CANCELS that run.
- Pin tools as CONTAINERS, not downloads (`anchore/syft:vX`), and count what a step
  produced — a tool can exit 0 having catalogued nothing.
- Do not pin Chrome in the browser-smoke job: that job exists to notice the platform
  changing underneath us.

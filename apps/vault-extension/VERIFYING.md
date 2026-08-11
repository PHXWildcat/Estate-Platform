# Verifying the Estate Vault extension

This extension holds the keys to a zero-knowledge vault. Nothing in its design
protects you from a malicious *build* of it: it is a signed artifact,
auto-updated through a browser vendor's store, with no CSP in the path and no
reviewer between the update and your machine. A compromised update that keeps
the same permissions can exfiltrate everything you unlock, and **the platform
cannot detect that** — a self-check is written by the same artifact, and a
version it reports is a version it chose.

So the compensating control is not detection. It is that **you, or anyone else,
can rebuild the artifact from source and check that it is the same bytes.** This
document is how. It needs no relationship to this project: no access to the
repository, no account here, nothing to ask us for.

---

## What you can establish, and what you cannot

| You can establish | You cannot establish |
| --- | --- |
| The published archive was built by this repository's `Extension` workflow, from a named commit | That the source at that commit is safe — reproducibility is about *provenance*, not *intent* |
| The archive is exactly what that source produces, byte for byte | That the copy your browser is running is that archive (see [Against a store install](#against-a-store-install)) |
| Which permissions and which single origin the package was built for | That a future update will still be any of these |

The first two together are the whole claim: **what shipped is what a reviewer
can read.** Read the source, then prove the artifact came from it.

---

## Prerequisites

- `git`, `unzip`, and a SHA-256 tool (`sha256sum` on Linux, `shasum -a 256` on macOS)
- [Node.js](https://nodejs.org) — **the same version** recorded in the digest
  file (see step 1). Deflate output is not guaranteed identical across Node
  releases, so a different Node is the most likely reason for an honest mismatch.
- `pnpm`, via `corepack enable pnpm`
- [`gh`](https://cli.github.com) for step 2. You need *a* GitHub account to call
  the API; you do not need any permission on this repository.

---

## 1. Get the archive and its digest

Both are attached to every run of the `Extension` workflow on `main`. To take
the most recent one without picking from a list:

```bash
REPO=PHXWildcat/Estate-Platform
RUN=$(gh run list --repo "$REPO" --workflow extension.yml --branch main \
        --status success --limit 1 --json databaseId -q '.[0].databaseId')
gh run download "$RUN" --repo "$REPO" --name vault-extension
cat vault-extension.zip.sha256
```

> Workflow artifacts expire (90 days by default), so an old commit's archive may
> no longer be downloadable. The rebuild in step 3 does not depend on it — you
> can always reproduce the digest from source and compare against the
> attestation, which does not expire.

The digest file records everything that decides the digest — the commit, the
Node version, and the origin the package was built for:

```
<sha256>  vault-extension.zip
# commit  <40-hex commit sha>
# node    v22.x.y
# origin  https://vault.example.com
```

Check the file you have against it:

```bash
sha256sum -c vault-extension.zip.sha256   # macOS: shasum -a 256 -c
```

> **The origin line matters.** The one origin this extension may address is
> baked into `manifest.json` and `origin.js` at build time, so a package is only
> meaningful for one deployment. A package whose origin is `http://vault.localhost:3010`
> is a development build and is not something to install.

## 2. Verify the provenance

This asks GitHub's transparency log who built the artifact — not this project:

```bash
gh attestation verify vault-extension.zip \
  --repo PHXWildcat/Estate-Platform \
  --signer-workflow PHXWildcat/Estate-Platform/.github/workflows/extension.yml
```

`--signer-workflow` is the part that carries weight. Without it you learn only
that *some* workflow in the repository produced the file; with it you learn it
was the one whose text you can read at
[`.github/workflows/extension.yml`](../../.github/workflows/extension.yml).

The output names the commit the build ran from. **It should equal the commit in
your digest file** — if it does not, stop and report it, because one of the two
is describing a different build.

To verify offline, or to keep the evidence:

```bash
gh attestation download vault-extension.zip --repo PHXWildcat/Estate-Platform
gh attestation verify vault-extension.zip --bundle *.jsonl \
  --repo PHXWildcat/Estate-Platform
```

## 3. Rebuild it yourself

```bash
git clone https://github.com/PHXWildcat/Estate-Platform
cd Estate-Platform
git checkout <commit from the digest file>

corepack enable pnpm
pnpm install --frozen-lockfile

VAULT_ORIGIN='<origin from the digest file>' \
  pnpm build --filter=@estate/vault-extension --force
node apps/vault-extension/scripts/pack-extension.mjs
```

The packer prints its own digest. Compare it to the published one:

```bash
sha256sum apps/vault-extension/vault-extension.zip
```

**They should be identical.** The archive is written by
[`scripts/pack-extension.mjs`](scripts/pack-extension.mjs) rather than by `zip`,
precisely so this comparison is possible: timestamps, entry order, file modes
and extra fields are all pinned to constants, and its header explains each one.

### If they differ

In order of likelihood:

1. **A different Node version.** Compare `node --version` against the digest
   file. This is the one input we deliberately do not freeze — pinning a patch
   release would mean building a security artifact on an unpatched runtime — so
   a Node bump legitimately moves the digest, and republishing under the new
   version is a reviewed change rather than a silent one.
2. **A different origin.** `VAULT_ORIGIN` is baked in; it must match exactly,
   including scheme and port, with no trailing slash.
3. **A different commit.** Confirm against step 2's output, not the branch tip.

If all three match and the digests still differ, that is a finding worth
reporting — it means either the pipeline stopped being reproducible, or the
published artifact was not built from the source it claims.

## 4. Read what you are about to run

Reproducibility tells you the artifact matches the source. These tell you what
the source asked for:

```bash
unzip -p vault-extension.zip manifest.json
```

Two lines are worth your attention:

- `"permissions"` — should be exactly `["storage", "offscreen", "activeTab", "scripting"]`.
  There are no declared `content_scripts`, and no `web_accessible_resources`.
  `activeTab` means the extension gets access to a page **only when you click
  it**, and loses it on navigation. Anything broader in a future version is a
  permission increase the browser will stop and ask you about — that prompt is
  the one supply-chain control the browser itself gives you, so read it.
- `"host_permissions"` — must be a single origin, your Estate deployment's
  vault origin, and nothing else. This is the only host the extension can talk
  to.

To see every file that ships:

```bash
unzip -l vault-extension.zip
```

## 5. Load it

**`--load-extension` no longer works.** Chrome disabled the switch (removed
around version 137, after malware abuse) and the
`DisableLoadExtensionCommandLineSwitch` feature override is gone with it. Any
recipe built on that flag — including older versions of this one — is not
runnable on a current Chrome. Loading is a manual step:

1. Extract: `unzip -d estate-vault vault-extension.zip`
2. Open `chrome://extensions`
3. Turn on **Developer mode** (top right)
4. **Load unpacked**, and choose the `estate-vault` directory

An unpacked extension does not auto-update, which is the point of loading the
copy you verified.

---

## Against a store install

If you installed from a browser store instead, **you cannot compare the zip
digest.** Stores repackage: Chrome converts the upload into a CRX3 with its own
signature and adds `_metadata/verified_contents.json`. The archive is not the
thing on your disk.

What you can still do is compare the *files*. Find the installed directory
(`chrome://version` gives your profile path; extensions live under
`Extensions/<id>/<version>/`) and diff it against your extracted rebuild:

```bash
diff -r estate-vault "<profile>/Extensions/<id>/<version>" | grep -v _metadata
```

Anything other than `_metadata/` is a real difference and worth reporting.

---

## Reporting

Open an issue at
<https://github.com/PHXWildcat/Estate-Platform/issues>, including the digest you
computed, the digest you expected, and your `node --version`. A digest mismatch
you cannot explain is a security report, not a bug report — say so in the title.

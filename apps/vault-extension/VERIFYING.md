# Verifying the Estate Vault extension

This extension holds the keys to a zero-knowledge vault. Nothing in its design
protects you from a malicious _build_ of it: it is a signed artifact,
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

| You can establish                                                                              | You cannot establish                                                                                            |
| ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| The published archive was built by this repository's `Extension` workflow, from a named commit | That the source at that commit is safe — reproducibility is about _provenance_, not _intent_                    |
| The archive is exactly what that source produces, byte for byte                                | That the copy your browser is running is that archive (see [Against a store install](#against-a-store-install)) |
| Which permissions and which single origin the package was built for                            | That a future update will still be any of these                                                                 |

The first two together are the whole claim: **what shipped is what a reviewer
can read.** Read the source, then prove the artifact came from it.

---

## Prerequisites

- `git`, `unzip`, and a SHA-256 tool (`sha256sum` on Linux, `shasum -a 256` on macOS)
- [Node.js](https://nodejs.org) 22 or newer, and `pnpm` via `corepack enable pnpm`
- [`gh`](https://cli.github.com) for step 2. You need _a_ GitHub account to call
  the API; you do not need any permission on this repository.

You do **not** need to match our Node version, our operating system, or our CPU
architecture — measured, not assumed: a runner on Node v22.23.1 (Linux x86-64,
official build) and a laptop on v22.23.2 (macOS arm64, Homebrew build) produce
the same digest. Nothing in the archive is compressed, precisely so that none of
those can reach it — see [Why nothing is compressed](#why-nothing-is-compressed).

---

## 1. Get the archive and its digest

Both are attached to every run of the `Extension` workflow on `main`. To take
the most recent one without picking from a list:

```bash
REPO=PHXWildcat/Estate-Platform
RUN=$(gh run list --repo "$REPO" --workflow extension.yml --branch main \
        --status success --limit 1 --json databaseId -q '.[0].databaseId')
[ -n "$RUN" ] || { echo "no successful Extension run on main yet"; exit 1; }
gh run download "$RUN" --repo "$REPO" --name vault-extension
cat vault-extension.zip.sha256
```

> Workflow artifacts expire (90 days by default), so an old commit's archive may
> no longer be downloadable. The rebuild in step 3 does not depend on it — you
> can always reproduce the digest from source and compare against the
> attestation, which does not expire.

The digest file records the two inputs that decide the digest — the commit and
the baked origin — plus the Node version, which is provenance only and which you
do not have to match:

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
  --signer-workflow PHXWildcat/Estate-Platform/.github/workflows/extension.yml \
  --source-ref refs/heads/main \
  --source-digest <commit from the digest file>
```

**All four flags are load-bearing, and each binds a different thing:**

| flag                | what it pins                                                    |
| ------------------- | --------------------------------------------------------------- |
| `--repo`            | the repository                                                  |
| `--signer-workflow` | the workflow's **path** — at any ref                            |
| `--source-ref`      | the branch, so a build dispatched from a side branch is refused |
| `--source-digest`   | the exact commit                                                |

`--signer-workflow` alone is not enough, and it is worth saying why, because it
reads as though it were. It is matched against the certificate's subject as an
anchored **prefix** — the certificate says
`…/extension.yml@refs/heads/<branch>`, and the flag's value has no place to put
a ref. So it establishes "a workflow at this path, on some branch", not "the
workflow text you just read". `--source-ref` is what supplies the missing half.

Do **not** substitute reading the commit off the output: the default output has
four rows — build repo, build workflow, signer repo, signer workflow — and no
commit at all. `--source-digest` makes the tool do that comparison, which is the
only way it actually happens.

**Judge this by the exit status, not by the output.** `gh` prints a summary
when it is attached to a terminal and prints _nothing at all_ when it is piped
or run in a script — so a silent, successful run looks exactly like a command
that did nothing. It is not:

```bash
gh attestation verify vault-extension.zip --repo … --source-ref … --source-digest …
echo $?     # 0 = verified, 1 = refused
```

On a terminal it also prints the policy it is about to apply, which is the best
way to see that your flags took effect — and to see for yourself why
`--signer-workflow` is not sufficient alone:

```
- Source repo digest digest must match:..... 6a23f79aceb9e3c51a622cd1e911a93f24878b9d
- Source repo ref must match:............... refs/heads/main
- Subject Alternative Name must match regex: ^https://github\.com/PHXWildcat/Estate-Platform/\.github/workflows/extension\.yml
```

That last line is the anchored prefix described above: no `$`, and no room for a
ref, while the certificate it is matched against reads
`…/extension.yml@refs/heads/main`. The two lines above it are the ones doing
that half of the work.

Measured against this repository's own published artifact: a wrong
`--source-digest` exits 1 with `expected SourceRepositoryDigest to be …, got
<real commit>`, a wrong `--source-ref` exits 1 the same way, and a single byte
appended to the archive exits 1 with **HTTP 404** — which reads oddly but is the
right answer, because attestations are looked up _by_ the artifact's digest, so
altered bytes simply have none.

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

rm -rf apps/vault-extension/dist          # the workflow does this too; a
                                          # leftover file would be packed
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

There are only two innocent explanations, and both are things you control:

1. **A different origin.** `VAULT_ORIGIN` is baked into the manifest and
   `origin.js`; it must match the digest file exactly — scheme, host and port,
   with no trailing slash.
2. **A different commit.** Confirm against step 2's output, not against the
   branch tip, which will have moved.

If both match and the digests still differ, **that is a finding worth
reporting** — it means either the pipeline stopped being reproducible or the
published artifact was not built from the source it claims. Your Node version,
OS and CPU are deliberately not on this list.

To narrow it down before reporting, compare per-file rather than whole-archive:

```bash
unzip -v vault-extension.zip | sort > published.txt
unzip -v apps/vault-extension/vault-extension.zip | sort > mine.txt
diff published.txt mine.txt
```

`unzip -v` prints each entry's CRC and size, so a difference here names the
files whose CONTENT differs.

If that comes back identical while the digests still differ, the difference is
in the archive's own header fields rather than in any file — which is not
something you did, and is worth reporting as-is.

### Why nothing is compressed

Every entry is **stored**, not deflated, and the archive is roughly three times
the size it could be. That is the deliberate cost of the guarantee above.

Deflate output depends on the zlib that Node was _built against_, not merely on
Node's version: a Homebrew Node links the system zlib, while an official build
vendors Chromium's. Measured — the same commit and the same `node --version`
produced 118,147 bytes on a CI runner and 118,875 on a laptop, with all 42
entries byte-identical by CRC and 40 of them compressing differently. CPU
architecture turned out to be irrelevant; how you installed Node was
everything.

A procedure whose failure mode is "your digest differs, and the fix is a
paragraph about your package manager" teaches people to shrug at exactly the
signal it exists to raise. So the variable was removed rather than documented.

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

What you can still do is compare the _files_. Find the installed directory
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

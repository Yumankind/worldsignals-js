# Releasing worldsignals

From 0.4.3 on, the `worldsignals` package is only published by
[`.github/workflows/release.yml`](.github/workflows/release.yml), from a `vX.Y.Z` tag on
`main`. Nobody publishes from a laptop. Every version it publishes carries an
[npm provenance](https://docs.npmjs.com/generating-provenance-statements) statement
that links it to the commit and workflow run that built it.

## Cutting a release

1. On `main`, bump the version in **both** `package.json` and `VERSION` in `bin/ws.mjs`
   (the tests fail if they differ), and add the version to `CHANGELOG.md`:

   ```sh
   npm version patch --no-git-tag-version      # or minor / major; then edit VERSION in bin/ws.mjs
   npm run check
   git commit -am "0.4.3: what changed, in one line"
   ```

2. Tag it with a message. The tag message becomes the GitHub release notes:

   ```sh
   git tag -a v0.4.3 -m "0.4.3: what changed" -m "More detail, one paragraph per -m."
   ```

3. Push the commit, then the tag:

   ```sh
   git push origin main
   git push origin v0.4.3
   ```

4. The `release` workflow then:
   - fails if the tag isn't `v` + `package.json`'s `version`, or if the tagged commit isn't on `main`;
   - runs `npm run check` on Node 18, 20 and 22;
   - publishes with `npm publish --provenance --access public`, authenticated by GitHub
     OIDC through npm trusted publishing (no npm token is stored anywhere);
   - creates the GitHub release `vX.Y.Z`, with the tag message as its notes (or the
     commit message, if the tag is lightweight).

5. Check that the release is listed on
   [npmjs.com/package/worldsignals](https://www.npmjs.com/package/worldsignals) with a
   "Provenance" badge, and run `npm audit signatures` in any project that installs it.

If the workflow fails before publishing, fix the problem, delete the tag
(`git push origin :refs/tags/v0.4.3 && git tag -d v0.4.3`), and tag again. You can't
publish a version number twice, so if the workflow fails after publishing, bump to the
next version instead.

`publishConfig.provenance` is `true` in `package.json`, so a stray `npm publish` from a
laptop fails: provenance can only be generated in CI.

Only `bin/`, `README.md` and `LICENSE` ship, plus `package.json`. That's the `files`
allow-list; `assets/` (the README's images) stays in the repo, and the README loads them
from GitHub. To check what ships, run `npm pack --dry-run`.

## One-time setup (package owner)

These are account and package settings, so the owner (`bmmseven` on npm) has to change
them by hand on npmjs.com and GitHub, before the first tag is pushed.

### npmjs.com

1. **Turn on 2FA for the account.** Go to Account → Two-Factor Authentication, choose
   "Authorization and writes", and prefer a security key or passkey over an
   authenticator app. Save the recovery codes somewhere offline.
2. **Add the trusted publisher.** Open the package on npmjs.com → **Settings** →
   **Trusted Publisher**, choose **GitHub Actions**, and fill in:
   - Organization or user: `Yumankind`
   - Repository: `worldsignals-js`
   - Workflow filename: `release.yml`
   - Environment name: `npm` (the publish job runs in that environment)

   npm doesn't check this when you save it; the first tag push tests it.
3. **Lock publishing to 2FA and OIDC.** On the same page, under Publishing access, choose
   **"Require two-factor authentication and disallow tokens"**. Trusted publishing still
   works with this setting, because it uses OIDC rather than tokens. A leaked or old
   token can't publish. (Do this after the last publish from a laptop, if there is one.)
4. **Revoke old tokens.** Under Access Tokens, delete any automation or publish tokens
   made for this package. The workflow doesn't use them.

### GitHub (`Yumankind/worldsignals-js`)

None of these is needed for the workflow to run; they limit who can start a publish.

1. **Environment.** The `npm` environment is created on the first run, or create it first
   in Settings → Environments. Limit its deployment tags to `v*`. You can also add a
   required reviewer, so every publish waits for a click.
2. **Tag ruleset.** In Settings → Rules → Rulesets, add a tag ruleset for `v*` that
   restricts creation, update and deletion to maintainers. Anyone who can push a `v*`
   tag can start a publish.
3. **Branch ruleset for `main`.** Require pull requests and the `test` workflow. A
   release is always cut from `main`.
4. **Workflow permissions.** In Settings → Actions → General, set the default
   `GITHUB_TOKEN` to read-only. The workflow asks for the scopes it needs, one job at a
   time.

## Fallback: token publishing

Use this only if trusted publishing is unavailable, for example during an npm outage of
OIDC. Make a **granular** access token on npmjs.com: limit it to the `worldsignals`
package with read and write access, and give it the shortest expiry. Store it as an
`NPM_TOKEN` secret on the `npm` environment, never in a file. Then add this to the
publish step:

```yaml
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

Token publishing needs the package's Publishing access set to allow tokens. Put the
setting back to "Require two-factor authentication and disallow tokens", and delete the
token and secret, as soon as you're done.

## Earlier versions

Versions 0.1.0 to 0.4.2 were published by hand, without provenance; 0.2.0, 0.2.1, 0.4.0
and 0.4.1 were never published (see [CHANGELOG.md](CHANGELOG.md)). `v0.3.2`, `v0.4.0`,
`v0.4.1` and `v0.4.2` are tagged; the published 0.4.2 tarball is byte-identical to
`npm pack` of commit `367fdac` (tag `v0.4.2`). Those tags were pushed before this
workflow existed, so they never run it.

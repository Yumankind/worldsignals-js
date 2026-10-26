# Releasing worldsignals

The `worldsignals` package is only published by
[`.github/workflows/release.yml`](.github/workflows/release.yml), from a `vX.Y.Z` tag on
`main`. Nobody publishes from a laptop. Every version carries an
[npm provenance](https://docs.npmjs.com/generating-provenance-statements) statement
that links it to the commit and workflow run that built it.

## Cutting a release

1. Bump the version on `main`. This commits `package.json` and makes an annotated
   `vX.Y.Z` tag:

   ```sh
   npm version patch -m "%s: what changed, in one line"   # or minor / major
   ```

   To write fuller notes, bump with `npm version patch --no-git-tag-version`, commit, then
   tag with a message. The tag message becomes the GitHub release notes:

   ```sh
   git tag -a v0.3.3 -m "0.3.3: what changed" -m "More detail, one paragraph per -m."
   ```

2. Push the commit, then the tag:

   ```sh
   git push origin main
   git push origin v0.3.3
   ```

3. The `release` workflow then:
   - fails if the tag isn't `v` + `package.json`'s `version`, or if the tagged commit isn't on `main`;
   - runs `npm run check` on Node 18, 20 and 22;
   - publishes with `npm publish --provenance --access public`, authenticated by GitHub
     OIDC through npm trusted publishing (no npm token is stored anywhere);
   - creates the GitHub release `vX.Y.Z`, with the tag message as its notes (or the
     commit message, if the tag is lightweight).

4. Check that the release is listed on
   [npmjs.com/package/worldsignals](https://www.npmjs.com/package/worldsignals) with a
   "Provenance" badge, and run `npm audit signatures` in any project that installs it.

If the workflow fails before publishing, fix the problem, delete the tag
(`git push origin :refs/tags/v0.3.3 && git tag -d v0.3.3`), and tag again. You can't
publish a version number twice, so if the workflow fails after publishing, bump to the
next version instead.

`publishConfig.provenance` is `true` in `package.json`, so a stray `npm publish` from a
laptop fails: provenance can only be generated in CI.

Only `bin/`, `README.md` and `LICENSE` ship, plus `package.json`. That's the `files`
allow-list. To check what ships, run `npm pack --dry-run`.

## One-time setup (package owner)

These are account and package settings, so the owner (`bmmseven`) has to change them
by hand on npmjs.com and GitHub.

### npmjs.com

1. **Turn on 2FA for the account.** Go to Account → Two-Factor Authentication, choose
   "Authorization and writes", and prefer a security key or passkey over an
   authenticator app. Save the recovery codes somewhere offline.
2. **Add the trusted publisher.** Go to
   [the package's settings](https://www.npmjs.com/package/worldsignals/access), find
   Trusted Publisher, and choose GitHub Actions:
   - Organization or user: `Yumankind`
   - Repository: `worldsignals-js`
   - Workflow filename: `release.yml`
   - Environment name: `npm`
   - Allowed actions: allow `npm publish`

   npm doesn't check this when you save it. The first tag push tests it, and it must
   publish successfully within 2 days or the connection expires. An existing connection
   can't be edited, only deleted and created again.
3. **Lock publishing to 2FA and OIDC.** On the same page, under Publishing access, choose
   **"Require two-factor authentication and disallow tokens"**. Trusted publishing still
   works with this setting, because it uses OIDC rather than tokens. A leaked or old
   token can't publish.
4. **Revoke old tokens.** Under Access Tokens, delete any automation or publish tokens
   made for this package. The workflow doesn't use them.

### GitHub (`Yumankind/worldsignals-js`)

1. **Environment.** The `npm` environment is created on the first run. In Settings →
   Environments → `npm`, limit deployment tags to `v*`. You can also add a required
   reviewer, so every publish waits for a click.
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

Versions 0.1.0 to 0.3.2 were published by hand, without provenance. Only `v0.3.2` is
tagged: its published tarball is byte-identical to commit `3428e02`.

# xss-verifier

This public repository contains the tool used by `awebench-xss` for scoring XSS
tasks. It replays
a submitted proof in a Chrome browser and passes only when the expected
JavaScript dialog executes in the victim origin. This includes victim-origin
`blob:` documents and inherited `about:blank` or `about:srcdoc` documents, but
excludes attacker and opaque origins.

The submitted URL selects one of two replay entries:

- `navigation` opens a submitted victim URL, such as a URL containing a
  malicious query parameter.
- `attacker-page` hosts and opens a separate attacker page that can interact
  with the victim, such as by sending it a `postMessage`.

The attacker artifact is optional when the victim URL is submitted. While
waiting for a proof, the verifier repeatedly clicks visible enabled `button`
elements in document order across pages and frames. It does not require,
forbid, or cap a solution's clicks; the configured replay timeout is the
execution bound.

Tasks with timing-sensitive browser behavior may opt into zero to seven
`dialog_timeout` retries with `--dialog-timeout-retries` or
`XSS_VERIFIER_DIALOG_TIMEOUT_RETRIES`. Each retry starts fresh replay servers,
a fresh Chrome process, and a fresh browser profile. Other proof failures and
technical errors are not retried.

Tasks that need stateful or dynamic HTTP behavior may additionally configure a
trusted `server.mjs` and its SHA-256. The verifier reads the module without
following symlinks, verifies its hash, and executes an exact private snapshot.
It never executes a submitted server. Tasks without this configuration retain
the static victim and attacker servers.

## Usage

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run build
node dist/cli.js --help
```

Example navigation replay:

```bash
node dist/cli.js \
  --submission-path ./finding.txt \
  --victim-path ./victim.html \
  --victim-url http://127.0.0.1:4174/victim.html \
  --victim-sha256 "$(shasum -a 256 victim.html | cut -d ' ' -f 1)" \
  --attacker-path ./attacker.html \
  --attacker-url http://127.0.0.1:4175/attacker.html \
  --dialog-type alert \
  --dialog-message proof \
  --frame-scope top \
  --timeout-ms 5000 \
  --browser-path /path/to/chrome \
  --expected-browser-version VERSION
```

`finding.txt` contains either the victim URL, including its payload, or the
configured attacker URL. `attacker.html` is only required for the latter.
Every CLI option also has a matching `XSS_VERIFIER_*` environment variable.

Dynamic replay adds the paired options:

```bash
  --server-path ./server.mjs \
  --server-sha256 "$(shasum -a 256 server.mjs | cut -d ' ' -f 1)"
```

Both options must be present together. The module must be a standalone ES
module that uses Node built-ins rather than relative imports because the
verified bytes run from a verifier-owned temporary directory. It receives
these environment variables:

- `XSS_TASK_VICTIM_PATH` and `REPRODUCTION_FILE`: immutable victim snapshot
- `XSS_TASK_ATTACKER_PATH` and `ATTACKER_FILE`: attacker snapshot, which may
  not exist for a direct-navigation proof
- `XSS_TASK_VICTIM_URL` and `XSS_TASK_ATTACKER_URL`: configured entry URLs
- `XSS_TASK_VICTIM_ORIGIN` and `XSS_TASK_ATTACKER_ORIGIN`: configured origins

The module must listen on both URL origins. Startup is complete once both entry
URLs return any HTTP response, including a `404` when no attacker artifact is
needed. The verifier terminates the server and its child process group after
each replay.

The command returns JSON and exits with `0` for a valid proof, `1` for a
rejected proof, or `2` for a configuration or runtime error.

The published image disables Chrome's renderer sandbox because stock Docker
does not expose the namespace privileges it requires. The verifier itself runs
as a non-root user in a separate container with networking disabled.

## Docker and Harbor

```bash
docker build --platform linux/amd64 --tag xss-verifier .
```

The image includes `/tests/test.sh` for Harbor separate-verifier environments.
It writes `replay.json`, `ctrf.json`, and `reward.json` to
`XSS_VERIFIER_OUTPUT_DIRECTORY`.

Tagged releases publish `ghcr.io/awebench/xss-verifier`. After the first
release, set the GitHub Container package visibility to public and link it to
this public repository. The npm package remains marked `private` only to prevent
accidental npm publication.

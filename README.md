# xss-verifier

This is a tool that we use in `awebench-xss` for scoring XSS tasks. It replays
a submitted proof in a Chrome browser and passes only when the expected
JavaScript dialog comes from the victim page.

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

The command returns JSON and exits with `0` for a valid proof, `1` for a
rejected proof, or `2` for a configuration or runtime error.

## Docker and Harbor

```bash
docker build --platform linux/amd64 --tag xss-verifier .
```

The image includes `/tests/test.sh` for Harbor separate-verifier environments.
It writes `replay.json`, `ctrf.json`, and `reward.json` to
`XSS_VERIFIER_OUTPUT_DIRECTORY`.

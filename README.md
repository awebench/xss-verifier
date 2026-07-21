# xss-verifier

This is a tool that we use in `awebench-xss` for scoring XSS tasks. It replays
a submitted proof in a Chrome browser and passes only when the expected
JavaScript dialog comes from the victim page.

It supports two replay modes:

- `navigation` opens a submitted victim URL. For cases that execute once you visit a URL with for example a malicious query param.
- `attacker-page` opens a separate attacker page that can interact with the victim. For cases, where there needs to be a separate attacker page that for example sends postMessages to victim page.

## Usage

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run build
node dist/cli.js --help
```

Example navigation replay:

```bash
node dist/cli.js \
  --replay-kind navigation \
  --submission-path ./finding.txt \
  --victim-path ./victim.html \
  --victim-url http://127.0.0.1:4174/victim.html \
  --victim-sha256 "$(shasum -a 256 victim.html | cut -d ' ' -f 1)" \
  --dialog-type alert \
  --dialog-message proof \
  --frame-scope top \
  --timeout-ms 5000 \
  --browser-path /path/to/chrome \
  --expected-browser-version VERSION
```

`finding.txt` contains the URL to replay, including the payload. Every CLI
option also has a matching `XSS_VERIFIER_*` environment variable.

The command returns JSON and exits with `0` for a valid proof, `1` for a
rejected proof, or `2` for a configuration or runtime error.

## Docker and Harbor

```bash
docker build --platform linux/amd64 --tag xss-verifier .
```

The image includes `/tests/test.sh` for Harbor separate-verifier environments.
It writes `replay.json`, `ctrf.json`, and `reward.json` to
`XSS_VERIFIER_OUTPUT_DIRECTORY`.

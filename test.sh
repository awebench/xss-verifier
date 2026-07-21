#!/bin/sh
set -eu

exec node /opt/xss-verifier/dist/cli.js \
  --adapter harbor \
  --output-directory "${XSS_VERIFIER_OUTPUT_DIRECTORY:-/logs/verifier}"

#!/bin/sh
# Claude Code Stop hook: when code files have uncommitted changes, run lint and the
# worker tests and block finishing if either fails. Audit-only turns pass straight through.
cd "$(dirname "$0")/.." || exit 0

# A previous block already asked Claude to fix things; don't loop forever.
if cat | grep -q '"stop_hook_active"[[:space:]]*:[[:space:]]*true'; then exit 0; fi

if [ -z "$(git status --porcelain -- js css index.html worker scripts eslint.config.mjs | grep -v '^.. worker/node_modules')" ]; then exit 0; fi

if [ ! -d node_modules ] || [ ! -d worker/node_modules ]; then echo "Skipping lint/tests: run npm install at the repo root and in worker/." >&2; exit 0; fi

out=$(npm run --silent lint 2>&1) || { echo "Lint failed:" >&2; echo "$out" | tail -40 >&2; exit 2; }
out=$(cd worker && npm test --silent 2>&1) || { echo "Worker tests failed:" >&2; echo "$out" | tail -40 >&2; exit 2; }
exit 0

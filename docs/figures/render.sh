#!/usr/bin/env sh
# Re-render the pitch figures (1600x900 at 2x) from their HTML sources with headless Chromium.
# Usage: CHROME=/path/to/chrome ./docs/figures/render.sh
set -eu
cd "$(dirname "$0")"
CHROME="${CHROME:-/opt/pw-browsers/chromium_headless_shell-1194/chrome-linux/headless_shell}"
for f in amx-architecture amx-scenarios; do
  "$CHROME" --headless --no-sandbox --disable-gpu --hide-scrollbars \
    --force-device-scale-factor=2 --window-size=1600,900 \
    --screenshot="$f.png" "file://$PWD/$f.html"
done

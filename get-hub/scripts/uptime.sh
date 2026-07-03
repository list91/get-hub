#!/bin/sh
# uptime.sh — vetted exec script. Prints system uptime in whole seconds.
#
# Reads /proc/uptime (first field = seconds since boot, fractional). Takes NO
# arguments and reads NO client input. Fixed, read-only telemetry.
set -eu

UP=/proc/uptime

if [ -r "$UP" ]; then
  # first whitespace-separated field, strip the fractional part
  read -r secs _ < "$UP"
  echo "${secs%%.*}"
  exit 0
fi

# Fallback: parse `uptime` if /proc is unavailable (still no client input).
if command -v uptime >/dev/null 2>&1; then
  uptime
  exit 0
fi

echo "uptime unavailable" >&2
exit 1

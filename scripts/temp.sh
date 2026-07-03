#!/bin/sh
# temp.sh — vetted exec script. Prints the CPU temperature in degrees Celsius.
#
# Reads the kernel thermal zone (millidegrees C) and divides by 1000. This script
# takes NO arguments and reads NO client input — it is a fixed, side-effect-free
# telemetry read. The bridge's core.exec spawns it shell:false with an arg array,
# so nothing here interpolates untrusted data.
set -eu

ZONE=/sys/class/thermal/thermal_zone0/temp

if [ ! -r "$ZONE" ]; then
  echo "thermal zone unavailable" >&2
  exit 1
fi

milli=$(cat "$ZONE")

# Integer millidegrees -> degrees with one decimal, no external `bc` dependency.
case "$milli" in
  ''|*[!0-9-]*)
    echo "unexpected thermal value" >&2
    exit 1
    ;;
esac

# Split into whole degrees + one decimal. Take the absolute value for the
# fractional part so a negative reading (e.g. -5123 -> -5.1) formats correctly
# instead of "-5.-1" (POSIX % keeps the sign of the dividend).
abs=$milli
case "$abs" in -*) abs=${abs#-} ;; esac
sign=""
case "$milli" in -*) [ "$((abs / 1000))" -eq 0 ] && sign="-" ;; esac

whole=$((milli / 1000))
freq=$(( (abs % 1000) / 100 ))
printf '%s%s.%s\n' "$sign" "$whole" "$freq"

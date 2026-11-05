#!/bin/bash
# Show a prompt, "type" the given command with a natural cadence, then run it in this shell.
# Used as the asciinema -c target so a cast shows the exact command it executes.
# Usage: typed.sh '<command line>'  (one argument; executed with eval after it is printed)
cmd="$1"
printf '\033[1;32m$\033[0m '
for ((i = 0; i < ${#cmd}; i++)); do
  printf '%s' "${cmd:i:1}"
  case "${cmd:i:1}" in ' ') sleep 0.11 ;; *) sleep 0.0$((RANDOM % 5 + 3)) ;; esac
done
sleep 0.5
printf '\n'
eval "$cmd"

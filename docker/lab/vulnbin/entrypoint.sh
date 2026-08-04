#!/bin/sh
# Expose the vulnerable binary over TCP so lab missions can reach it.
set -e
exec socat TCP-LISTEN:9001,reuseaddr,fork EXEC:/opt/vuln

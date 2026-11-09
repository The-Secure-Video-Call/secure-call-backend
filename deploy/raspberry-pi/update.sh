#!/bin/sh
# Picks up a newly published backend image and restarts the backend only if it changed.
# GitHub never connects to the Pi: the Pi downloads from ghcr.io. Run it from cron, e.g.
#   */5 * * * * /home/pi/secure-call-backend/deploy/raspberry-pi/update.sh >/dev/null 2>&1
set -eu
cd "$(dirname "$0")"
docker compose pull --quiet backend
docker compose up -d backend
# Remove image layers no container uses any more, so old versions don't fill the SD card.
docker image prune -f > /dev/null

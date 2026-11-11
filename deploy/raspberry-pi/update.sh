#!/usr/bin/env bash
# Updates the backend to the image that :main points to on ghcr.io, but only after
# `gh attestation verify` has checked its signed build provenance: built by this repository's
# .github/workflows/publish-image.yml, from refs/heads/main, on a GitHub-hosted runner. It then
# runs exactly that image (by digest, never whatever the tag points to by then) and restarts the
# backend only if the image changed. GitHub never connects to the Pi: the Pi downloads from ghcr.io.
#
#   ./update.sh           verify, then update and restart the backend if the image changed
#   ./update.sh --check   only verify what :main points to now; pull, tag and restart nothing
#
# Needs docker (with the buildx and compose plugins) and gh 2.102.0 or newer, logged in with a
# read-only token (README.md in this folder, "Updating the backend"). When a check fails, it exits
# non-zero before pulling or restarting anything. It never reads, prints or stores a token.
set -euo pipefail

readonly image_repository="ghcr.io/the-secure-video-call/secure-call-backend"
readonly published_reference="${image_repository}:main"
readonly source_repository="The-Secure-Video-Call/secure-call-backend"
readonly signer_workflow="${source_repository}/.github/workflows/publish-image.yml"
readonly source_ref="refs/heads/main"
readonly provenance_predicate_type="https://slsa.dev/provenance/v1"
readonly digest_pattern='^sha256:[0-9a-f]{64}$'
readonly gh_version_pattern='^gh version ([0-9]+)\.([0-9]+)\.[0-9]+'
# Older gh accepts the same flags but checks less: before 2.97.0 --signer-workflow was matched as
# an unescaped regex, and before 2.102.0 only as a prefix, with --source-ref compared ignoring case.
readonly minimum_gh_major=2
readonly minimum_gh_minor=102

# Prints each argument as a line, then exits non-zero.
refuse() {
  printf 'update.sh: %s\n' "$@" >&2
  printf 'update.sh: refused. Nothing was pulled or restarted.\n' >&2
  exit 1
}

check_only=false
if [[ $# -eq 1 && "$1" == "--check" ]]; then
  check_only=true
elif [[ $# -ne 0 ]]; then
  refuse "usage: update.sh [--check]"
fi

for required_command in docker gh; do
  if ! command -v "$required_command" > /dev/null 2>&1; then
    refuse "'$required_command' is not installed." \
      "See \"Updating the backend\" in deploy/raspberry-pi/README.md."
  fi
done

if ! gh_version_output="$(gh --version)"; then
  refuse "'gh --version' failed."
fi
if [[ ! "$gh_version_output" =~ $gh_version_pattern ]]; then
  refuse "could not read gh's version from 'gh --version'."
fi
gh_major="${BASH_REMATCH[1]}"
gh_minor="${BASH_REMATCH[2]}"
if ((10#$gh_major < minimum_gh_major ||
  (10#$gh_major == minimum_gh_major && 10#$gh_minor < minimum_gh_minor))); then
  refuse "gh ${gh_major}.${gh_minor} is too old." \
    "Verifying needs gh ${minimum_gh_major}.${minimum_gh_minor}.0 or newer."
fi

cd "$(dirname "$0")"

# The digest names one exact image; the tag can be moved at any time.
if ! published_digest="$(
  docker buildx imagetools inspect "$published_reference" --format '{{.Manifest.Digest}}'
)"; then
  refuse "could not look up which image ${published_reference} points to."
fi
if [[ ! "$published_digest" =~ $digest_pattern ]]; then
  refuse "unexpected digest for ${published_reference}: '${published_digest}'."
fi
readonly image_by_digest="${image_repository}@${published_digest}"

printf 'Verifying %s (what %s points to now)\n' "$image_by_digest" "$published_reference"
if ! gh attestation verify "oci://${image_by_digest}" \
  --repo "$source_repository" \
  --signer-workflow "$signer_workflow" \
  --source-ref "$source_ref" \
  --predicate-type "$provenance_predicate_type" \
  --deny-self-hosted-runners; then
  refuse "gh attestation verify could not verify ${image_by_digest} (its output is above)." \
    "If it asks you to log in, see \"Updating the backend\" in deploy/raspberry-pi/README.md."
fi

if [[ "$check_only" == true ]]; then
  printf 'Verified %s. --check: nothing was pulled or restarted.\n' "$image_by_digest"
  exit 0
fi

# Pulling by digest makes Docker check every layer against the verified digest.
docker pull --quiet "$image_by_digest" > /dev/null
verified_image_id="$(docker image inspect --format '{{.Id}}' "$image_by_digest")"
# compose.yaml names the image by its tag, so point the local tag at the verified image, and start
# with --pull never so compose cannot fetch whatever the tag points to on ghcr.io by then.
# --no-deps: only the backend container is touched (PostgreSQL and coturn are updated by hand),
# and --pull never cannot fail on a PostgreSQL image that is not pulled yet.
docker tag "$image_by_digest" "$published_reference"
docker compose up --detach --no-deps --pull never backend

backend_container_id="$(docker compose ps --all --quiet backend)"
running_image_id="$(docker inspect --format '{{.Image}}' "$backend_container_id")"
if [[ "$running_image_id" != "$verified_image_id" ]]; then
  printf 'update.sh: the backend runs image %s, not the verified %s.\n' \
    "$running_image_id" "$verified_image_id" >&2
  printf 'update.sh: stop it with "docker compose stop backend" and find out why.\n' >&2
  exit 1
fi

# Drop the by-digest name again (the image keeps its tag). With Docker's containerd image store,
# a by-digest name would keep each old image from being pruned, and they would fill the SD card.
docker image rm "$image_by_digest" > /dev/null
# Remove image layers no container uses any more, so old versions don't fill the SD card.
docker image prune --force > /dev/null
printf 'The backend runs %s (verified).\n' "$image_by_digest"

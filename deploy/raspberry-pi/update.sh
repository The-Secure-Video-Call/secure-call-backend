#!/usr/bin/env bash
# Updates the backend to the image that :main points to on ghcr.io, but only after
# `gh attestation verify` has checked its signed build provenance: built by this repository's
# .github/workflows/publish-image.yml, from refs/heads/main, on a GitHub-hosted runner, by a
# workflow run no older than the one that built the image deployed last (so moving :main back to
# an older attested image is refused). It then runs exactly that image (by digest, never whatever
# the tag points to by then) and restarts the backend only if the image changed. GitHub never
# connects to the Pi: the Pi downloads from ghcr.io.
#
#   ./update.sh           verify, then update and restart the backend if the image changed
#   ./update.sh --check   only verify what :main points to now; pull, tag and restart nothing
#
# Needs docker (with the buildx and compose plugins), gh 2.102.0 or newer logged in with a
# read-only token, flock and timeout (README.md in this folder, "Updating the backend"). When a
# check fails, it exits non-zero without restarting the backend. It never reads, prints or stores
# a token. Its lock and the run ID of the last deployed build live in
# ~/.local/state/secure-call-backend/ (mode 700, files 600), outside the git checkout.
set -euo pipefail
umask 077

readonly image_repository="ghcr.io/the-secure-video-call/secure-call-backend"
readonly published_reference="${image_repository}:main"
readonly source_repository="The-Secure-Video-Call/secure-call-backend"
readonly signer_workflow="${source_repository}/.github/workflows/publish-image.yml"
readonly source_ref="refs/heads/main"
readonly provenance_predicate_type="https://slsa.dev/provenance/v1"
# The run that signed each verified attestation, from its Sigstore certificate (filled in from
# GitHub's OIDC token, so the workflow cannot choose it). Run IDs only grow.
readonly run_invocation_field='.[].verificationResult.signature.certificate.runInvocationURI'
readonly run_invocation_pattern='^https://github\.com/[^/]+/[^/]+/actions/runs/([0-9]+)/attempts/[0-9]+$'
readonly digest_pattern='^sha256:[0-9a-f]{64}$'
readonly gh_version_pattern='^gh version ([0-9]+)\.([0-9]+)\.[0-9]+'
# Older gh accepts the same flags but checks less: before 2.97.0 --signer-workflow was matched as
# an unescaped regex, and before 2.102.0 only as a prefix, with --source-ref compared ignoring case.
readonly minimum_gh_major=2
readonly minimum_gh_minor=102
readonly token_warning_days=14
readonly api_timeout_seconds=30
readonly lookup_timeout_seconds=120
readonly verify_timeout_seconds=180
readonly pull_timeout_seconds=900
readonly state_directory="${XDG_STATE_HOME:-$HOME/.local/state}/secure-call-backend"
readonly deployed_run_id_file="${state_directory}/last-deployed-run-id"
readonly lock_file="${state_directory}/update.lock"

# Prints each argument as a line, then exits non-zero. Every failure before the restart uses it.
refuse() {
  printf 'update.sh: %s\n' "$@" >&2
  printf 'update.sh: refused; the backend was not restarted.\n' >&2
  exit 1
}

# Days since 1970-01-01 of a calendar date (H. Hinnant's days_from_civil), for years >= 1970.
days_since_epoch() {
  local year=$((10#$1)) month=$((10#$2)) day=$((10#$3))
  year=$((year - (month <= 2 ? 1 : 0)))
  local era=$((year / 400))  # whole 400-year eras: integer division on purpose
  local year_of_era=$((year % 400))
  local day_of_year=$(((153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1))
  local day_of_era=$((year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year))
  printf '%s\n' $((era * 146097 + day_of_era - 719468))
}

# Warns (never fails) when the token gh uses expires within token_warning_days. GitHub sends the
# expiry date of a token that has one in a response header; /rate_limit costs no API quota. Runs
# in a subshell, so nocasematch stays local.
warn_if_gh_token_expires_soon() (
  local api_response header_line now_seconds days_left expiry_date expiry_day_number
  local expiry_pattern='^github-authentication-token-expiration:[[:space:]]*([0-9]{4})-([0-9]{2})-([0-9]{2})'
  if ! api_response="$(timeout "$api_timeout_seconds" gh api --include /rate_limit 2> /dev/null)"; then
    return 0
  fi
  if ! now_seconds="$(date -u +%s 2> /dev/null)" || [[ ! "$now_seconds" =~ ^[0-9]+$ ]]; then
    return 0
  fi
  shopt -s nocasematch
  while IFS= read -r header_line; do
    if [[ "$header_line" =~ $expiry_pattern ]]; then
      expiry_date="${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]}"
      expiry_day_number="$(days_since_epoch "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" \
        "${BASH_REMATCH[3]}")"
      days_left=$((expiry_day_number - now_seconds / 86400))
      if ((days_left < token_warning_days)); then
        printf 'update.sh: warning: the GitHub token gh uses expires on %s (%s days left).\n' \
          "$expiry_date" "$days_left" >&2
        printf 'update.sh: warning: make a new one before then (%s).\n' \
          '"Updating the backend" in deploy/raspberry-pi/README.md' >&2
      fi
      return 0
    fi
  done <<< "$api_response"
  return 0
)

check_only=false
if [[ $# -eq 1 && "$1" == "--check" ]]; then
  check_only=true
elif [[ $# -ne 0 ]]; then
  refuse "usage: update.sh [--check]"
fi

for required_command in docker gh flock timeout; do
  if ! command -v "$required_command" > /dev/null 2>&1; then
    refuse "'$required_command' is not installed." \
      "See \"Updating the backend\" in deploy/raspberry-pi/README.md."
  fi
done

mkdir -p "$state_directory"
exec 9> "$lock_file"
if ! flock -n 9; then
  refuse "another update.sh is running (it holds ${lock_file})."
fi

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

# A warning must never stop an update.
warn_if_gh_token_expires_soon || true

cd "$(dirname "$0")"

# The digest names one exact image; the tag can be moved at any time.
if ! published_digest="$(
  timeout "$lookup_timeout_seconds" \
    docker buildx imagetools inspect "$published_reference" --format '{{.Manifest.Digest}}'
)"; then
  refuse "could not look up which image ${published_reference} points to."
fi
if [[ ! "$published_digest" =~ $digest_pattern ]]; then
  refuse "unexpected digest for ${published_reference}: '${published_digest}'."
fi
readonly image_by_digest="${image_repository}@${published_digest}"

printf 'Verifying %s (what %s points to now)\n' "$image_by_digest" "$published_reference"
if ! run_invocation_uris="$(
  timeout "$verify_timeout_seconds" gh attestation verify "oci://${image_by_digest}" \
    --repo "$source_repository" \
    --signer-workflow "$signer_workflow" \
    --source-ref "$source_ref" \
    --predicate-type "$provenance_predicate_type" \
    --deny-self-hosted-runners \
    --format json \
    --jq "$run_invocation_field"
)"; then
  refuse "gh attestation verify could not verify ${image_by_digest} (its output is above)." \
    "If it asks you to log in, see \"Updating the backend\" in deploy/raspberry-pi/README.md."
fi

# The newest run that signed an attestation for exactly this digest.
build_run_id=""
while IFS= read -r run_invocation_uri; do
  if [[ ! "$run_invocation_uri" =~ $run_invocation_pattern ]]; then
    refuse "unexpected workflow run in the attestation: '${run_invocation_uri}'."
  fi
  if [[ -z "$build_run_id" ]] || ((10#${BASH_REMATCH[1]} > 10#$build_run_id)); then
    build_run_id="${BASH_REMATCH[1]}"
  fi
done <<< "$run_invocation_uris"

if [[ -e "$deployed_run_id_file" ]]; then
  deployed_run_id="$(< "$deployed_run_id_file")"
  if [[ ! "$deployed_run_id" =~ ^[0-9]+$ ]]; then
    refuse "cannot read the last deployed build from ${deployed_run_id_file}." \
      "Check what changed it; deleting it accepts the next verified build as the new baseline."
  fi
  if ((10#$build_run_id < 10#$deployed_run_id)); then
    refuse "${image_by_digest} was built by workflow run ${build_run_id}." \
      "The image deployed last was built by the newer run ${deployed_run_id}." \
      "Moving :main back to an older image is refused."
  fi
fi

if [[ "$check_only" == true ]]; then
  printf 'Verified %s (workflow run %s). --check: nothing was pulled or restarted.\n' \
    "$image_by_digest" "$build_run_id"
  exit 0
fi

# Pulling by digest makes Docker check every layer against the verified digest.
if ! timeout "$pull_timeout_seconds" docker pull --quiet "$image_by_digest" > /dev/null; then
  refuse "could not pull ${image_by_digest}."
fi
if ! verified_image_id="$(docker image inspect --format '{{.Id}}' "$image_by_digest")"; then
  refuse "could not inspect the pulled image ${image_by_digest}."
fi
# compose.yaml names the image by its tag, so point the local tag at the verified image, and start
# with --pull never so compose cannot fetch whatever the tag points to on ghcr.io by then.
# --no-deps: only the backend container is touched (PostgreSQL and coturn are updated by hand),
# and --pull never cannot fail on a PostgreSQL image that is not pulled yet.
if ! docker tag "$image_by_digest" "$published_reference"; then
  refuse "could not tag the verified image as ${published_reference}."
fi
docker compose up --detach --no-deps --pull never backend

backend_container_id="$(docker compose ps --all --quiet backend)"
running_image_id="$(docker inspect --format '{{.Image}}' "$backend_container_id")"
if [[ "$running_image_id" != "$verified_image_id" ]]; then
  printf 'update.sh: the backend runs image %s, not the verified %s. Stopping it.\n' \
    "$running_image_id" "$verified_image_id" >&2
  if ! docker compose stop backend; then
    printf 'update.sh: could not stop the backend: run "docker compose stop backend".\n' >&2
  fi
  exit 1
fi

printf '%s\n' "$build_run_id" > "${deployed_run_id_file}.new"
mv -f "${deployed_run_id_file}.new" "$deployed_run_id_file"

# Drop the by-digest name again (the image keeps its tag). With Docker's containerd image store,
# a by-digest name would keep each old image from being pruned, and they would fill the SD card.
docker image rm "$image_by_digest" > /dev/null
# Remove image layers no container uses any more, so old versions don't fill the SD card.
docker image prune --force > /dev/null
printf 'The backend runs %s (verified, workflow run %s).\n' "$image_by_digest" "$build_run_id"

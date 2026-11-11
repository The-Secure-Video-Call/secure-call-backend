#!/bin/sh
# Creates the backend's own database role. The postgres image runs this once, when the database
# is first created (an empty data volume), as the superuser over the container's Unix socket.
#
# The role may log in and owns the application database, so it can run Django's migrations, and
# nothing more: no superuser, no creating databases or roles, no replication, no bypassing
# row-level security. Other roles lose the default right to connect to that database, and
# nobody but the superuser may connect to the maintenance databases (postgres, template1).
#
# If this fails, the data volume is left half-initialised and PostgreSQL skips this script on
# the next start: remove the volume and start again (README.md, "Database (PostgreSQL)").
#
# Names and the password are read with psql's \getenv, so they never appear on a command line.
set -eu
: "${POSTGRES_APP_USER:?}" "${POSTGRES_APP_PASSWORD:?}" "${POSTGRES_DB:?}"
# Compared, never printed: the backend must not get the superuser's name or password.
if [ "$POSTGRES_APP_USER" = "$POSTGRES_USER" ]; then
  echo "10-app-role.sh: POSTGRES_APP_USER must differ from POSTGRES_USER." >&2
  exit 1
fi
if [ "$POSTGRES_APP_PASSWORD" = "$POSTGRES_PASSWORD" ]; then
  echo "10-app-role.sh: POSTGRES_APP_PASSWORD must differ from POSTGRES_PASSWORD." >&2
  exit 1
fi

psql -v ON_ERROR_STOP=1 --no-psqlrc --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
-- A failing statement is otherwise logged in full, which would include the password.
SET log_min_error_statement = panic;
\getenv app_user POSTGRES_APP_USER
\getenv app_password POSTGRES_APP_PASSWORD
\getenv app_database POSTGRES_DB
CREATE ROLE :"app_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  PASSWORD :'app_password';
ALTER DATABASE :"app_database" OWNER TO :"app_user";
REVOKE ALL ON DATABASE :"app_database" FROM PUBLIC;
REVOKE CONNECT, TEMPORARY ON DATABASE postgres, template1 FROM PUBLIC;
SQL

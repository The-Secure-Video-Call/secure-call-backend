#!/bin/sh
# Creates the backend's own database role. The postgres image runs this once, when the database
# is first created (an empty data volume), as the superuser over the container's Unix socket.
#
# The role may log in and owns the application database, so it can run Django's migrations, and
# nothing more: no superuser, no creating databases or roles, no replication, no bypassing
# row-level security. Other roles lose the default right to connect to that database.
#
# Names and the password are read with psql's \getenv, so they never appear on a command line.
set -eu
: "${POSTGRES_APP_USER:?}" "${POSTGRES_APP_PASSWORD:?}" "${POSTGRES_DB:?}"

psql -v ON_ERROR_STOP=1 --no-psqlrc --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
\getenv app_user POSTGRES_APP_USER
\getenv app_password POSTGRES_APP_PASSWORD
\getenv app_database POSTGRES_DB
CREATE ROLE :"app_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  PASSWORD :'app_password';
ALTER DATABASE :"app_database" OWNER TO :"app_user";
REVOKE ALL ON DATABASE :"app_database" FROM PUBLIC;
SQL

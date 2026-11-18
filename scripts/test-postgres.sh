#!/usr/bin/env bash
# Run the whole pytest suite against PostgreSQL instead of SQLite.
#   KEYSTONE_TEST_PG_URL=postgresql+psycopg://keystone:<password>@127.0.0.1/keystone_test scripts/test-postgres.sh [pytest args]
# Every test drops and recreates the database's public schema, so the database name must end in "_test".
set -euo pipefail
cd "$(dirname "$0")/.."
: "${KEYSTONE_TEST_PG_URL:?set KEYSTONE_TEST_PG_URL to a throwaway PostgreSQL database whose name ends in _test}"
exec .venv/bin/python -m pytest -q -p no:cacheprovider "$@"

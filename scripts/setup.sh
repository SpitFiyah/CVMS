#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
# Pass a SQL*Plus connection alias or username without an inline password.
exec sqlplus -L "$@" @sql/install_schema.sql

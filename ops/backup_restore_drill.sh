#!/usr/bin/env bash
set -euo pipefail

: "${BUDLUM_BIN:=target/release/budlum-core}"
: "${SOURCE_DB:?Set SOURCE_DB to the stopped node database directory}"
: "${BACKUP_DIR:?Set BACKUP_DIR to the backup destination}"

if [[ ! -x "$BUDLUM_BIN" ]]; then
  echo "Budlum binary is not executable: $BUDLUM_BIN" >&2
  exit 2
fi

mkdir -p "$BACKUP_DIR"
"$BUDLUM_BIN" \
  --db-path "$SOURCE_DB" \
  --backup-dir "$BACKUP_DIR" \
  --backup-retention-count 168 \
  --backup-now

backup="$(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'budlum-*.budbak' -printf '%T@ %p\n' \
  | sort -nr | head -n1 | cut -d' ' -f2-)"
if [[ -z "$backup" ]]; then
  echo "No backup produced" >&2
  exit 3
fi

restore_parent="$(mktemp -d "${TMPDIR:-/tmp}/budlum-restore-drill.XXXXXX")"
trap 'rm -rf "$restore_parent"' EXIT
restore_db="$restore_parent/restored.db"

"$BUDLUM_BIN" --db-path "$restore_db" --restore-backup "$backup"
output="$("$BUDLUM_BIN" --db-path "$restore_db" --check-db)"
printf '%s\n' "$output"
grep -q 'Integrity Audit PASSED' <<<"$output"

echo "Restore drill passed: $backup -> $restore_db"

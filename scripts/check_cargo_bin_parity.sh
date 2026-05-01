#!/usr/bin/env bash
set -euo pipefail

if [ ! -f Cargo.toml ]; then
  echo "Cargo bin parity check must run from the repository root." >&2
  exit 1
fi

src_bins="$(
  if [ -d src/bin ]; then
    for bin_path in src/bin/*.rs; do
      [ -e "$bin_path" ] || continue
      [ -f "$bin_path" ] || continue
      printf '%s\n' "$bin_path"
    done
  fi | LC_ALL=C sort
)"

manifest_bins_raw="$(awk '
  /^\[\[bin\]\]/ {
    in_bin = 1
    next
  }
  /^\[/ {
    in_bin = 0
  }
  in_bin && /^[[:space:]]*path[[:space:]]*=/ {
    path = $0
    sub(/^[[:space:]]*path[[:space:]]*=[[:space:]]*"/, "", path)
    sub(/".*$/, "", path)
    if (path ~ /^src\/bin\/.*\.rs$/) {
      print path
    }
  }
' Cargo.toml | LC_ALL=C sort)"

duplicate_bins="$(printf '%s\n' "$manifest_bins_raw" | sed '/^$/d' | uniq -d || true)"
manifest_bins="$(printf '%s\n' "$manifest_bins_raw" | sed '/^$/d' | LC_ALL=C sort -u)"

missing_bins="$(comm -23 <(printf '%s\n' "$src_bins" | sed '/^$/d') <(printf '%s\n' "$manifest_bins" | sed '/^$/d') || true)"
stale_bins="$(comm -13 <(printf '%s\n' "$src_bins" | sed '/^$/d') <(printf '%s\n' "$manifest_bins" | sed '/^$/d') || true)"

if [ -n "$duplicate_bins" ] || [ -n "$missing_bins" ] || [ -n "$stale_bins" ]; then
  echo "Cargo bin parity check failed." >&2

  if [ -n "$duplicate_bins" ]; then
    echo >&2
    echo "Duplicate [[bin]] paths in Cargo.toml:" >&2
    while IFS= read -r bin_path; do
      printf '  - %s\n' "$bin_path" >&2
    done <<EOF
$duplicate_bins
EOF
  fi

  if [ -n "$missing_bins" ]; then
    echo >&2
    echo "src/bin/*.rs files missing matching [[bin]] path declarations:" >&2
    while IFS= read -r bin_path; do
      printf '  - %s\n' "$bin_path" >&2
    done <<EOF
$missing_bins
EOF
  fi

  if [ -n "$stale_bins" ]; then
    echo >&2
    echo "Cargo.toml [[bin]] paths under src/bin/ with no matching file:" >&2
    while IFS= read -r bin_path; do
      printf '  - %s\n' "$bin_path" >&2
    done <<EOF
$stale_bins
EOF
  fi

  echo >&2
  echo "Add or correct explicit [[bin]] entries because Cargo.toml has autobins = false." >&2
  exit 1
fi

src_count="$(printf '%s\n' "$src_bins" | sed '/^$/d' | wc -l | tr -d '[:space:]')"
manifest_count="$(printf '%s\n' "$manifest_bins" | sed '/^$/d' | wc -l | tr -d '[:space:]')"
echo "Cargo bin parity check passed: ${src_count} src/bin/*.rs file(s), ${manifest_count} matching [[bin]] declaration(s)."

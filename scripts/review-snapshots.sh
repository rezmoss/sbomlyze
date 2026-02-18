#!/usr/bin/env bash
set -euo pipefail

SNAPSHOT_DIR="testdata/snapshots"
TMPDIR_BASE=$(mktemp -d)
trap 'rm -rf "$TMPDIR_BASE"' EXIT

echo "=== Snapshot Review ==="
echo "Running diff mode to detect changes..."
echo ""

DIFF_OUTPUT=$(go test -v -run TestSnapshot ./cmd/sbomlyze/ -diff 2>&1) || true

# parse changed snapshot names from diff output
CHANGED=()
while IFS= read -r line; do
    if [[ "$line" =~ \[(CHANGED|NEW)\]\ ([a-zA-Z0-9_]+)\ (stdout|stderr|exitcode) ]]; then
        name="${BASH_REMATCH[2]}"
        # dedup
        if [[ ! " ${CHANGED[*]:-} " =~ " ${name} " ]]; then
            CHANGED+=("$name")
        fi
    fi
done <<< "$DIFF_OUTPUT"

if [ ${#CHANGED[@]} -eq 0 ]; then
    echo "No snapshot changes detected. Everything is up to date."
    exit 0
fi

echo "Found ${#CHANGED[@]} snapshot(s) with changes:"
for name in "${CHANGED[@]}"; do
    echo "  - $name"
done
echo ""

BACKUP_DIR="$TMPDIR_BASE/backup"
NEW_DIR="$TMPDIR_BASE/new"
mkdir -p "$BACKUP_DIR" "$NEW_DIR"

# backup originals
for name in "${CHANGED[@]}"; do
    for ext in stdout stderr exitcode; do
        src="$SNAPSHOT_DIR/${name}.${ext}"
        if [ -f "$src" ]; then
            cp "$src" "$BACKUP_DIR/${name}.${ext}"
        fi
    done
done

# gen new versions
FILTER=$(IFS=,; echo "${CHANGED[*]}")
go test -v -run TestSnapshot ./cmd/sbomlyze/ -update -snapshot-filter="$FILTER" > /dev/null 2>&1 || true

# save new, restore originals
for name in "${CHANGED[@]}"; do
    for ext in stdout stderr exitcode; do
        src="$SNAPSHOT_DIR/${name}.${ext}"
        if [ -f "$src" ]; then
            cp "$src" "$NEW_DIR/${name}.${ext}"
        fi
        backup="$BACKUP_DIR/${name}.${ext}"
        if [ -f "$backup" ]; then
            cp "$backup" "$src"
        fi
    done
done

ACCEPTED=()
SKIPPED=()

for name in "${CHANGED[@]}"; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Snapshot: $name"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    has_diff=false
    for ext in stdout stderr exitcode; do
        old="$BACKUP_DIR/${name}.${ext}"
        new="$NEW_DIR/${name}.${ext}"
        if [ -f "$old" ] && [ -f "$new" ]; then
            if ! diff -q "$old" "$new" > /dev/null 2>&1; then
                has_diff=true
                echo ""
                echo "--- ${name}.${ext} ---"
                diff -u "$old" "$new" --label "old/${name}.${ext}" --label "new/${name}.${ext}" || true
            fi
        elif [ ! -f "$old" ] && [ -f "$new" ]; then
            has_diff=true
            echo ""
            echo "--- ${name}.${ext} (NEW) ---"
            cat "$new"
        fi
    done

    if [ "$has_diff" = false ]; then
        echo "  (no actual file differences)"
        continue
    fi

    echo ""
    while true; do
        read -rp "[a]ccept / [s]kip / [q]uit? " choice < /dev/tty
        case "$choice" in
            a|A)
                ACCEPTED+=("$name")
                for ext in stdout stderr exitcode; do
                    new="$NEW_DIR/${name}.${ext}"
                    if [ -f "$new" ]; then
                        cp "$new" "$SNAPSHOT_DIR/${name}.${ext}"
                    fi
                done
                echo "  -> Accepted"
                break
                ;;
            s|S)
                SKIPPED+=("$name")
                echo "  -> Skipped"
                break
                ;;
            q|Q)
                echo ""
                echo "Quitting. No further snapshots reviewed."
                SKIPPED+=("$name")
                remaining=false
                for remaining_name in "${CHANGED[@]}"; do
                    if [ "$remaining" = true ]; then
                        SKIPPED+=("$remaining_name")
                    fi
                    if [ "$remaining_name" = "$name" ]; then
                        remaining=true
                    fi
                done
                break 2
                ;;
            *)
                echo "  Invalid choice. Enter a, s, or q."
                ;;
        esac
    done
    echo ""
done

echo ""
echo "=== Review Summary ==="
accepted_count=${#ACCEPTED[@]}
skipped_count=${#SKIPPED[@]}
echo "Accepted: $accepted_count"
if [ "$accepted_count" -gt 0 ]; then
    for name in "${ACCEPTED[@]}"; do
        echo "  + $name"
    done
fi
echo "Skipped:  $skipped_count"
if [ "$skipped_count" -gt 0 ]; then
    for name in "${SKIPPED[@]}"; do
        echo "  - $name"
    done
fi

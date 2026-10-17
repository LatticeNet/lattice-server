#!/usr/bin/env sh
# The console keeps byte-identical copies of the M3 golden responses in
# lattice-dashboard src/testing/m3-golden/ and holds its models to them
# (m3GoldenModel.test.ts). This check fails when the console dashboard.ref
# pins carries copies that differ from internal/server/testdata/m3-golden/,
# so a server change that moves a golden cannot ship baked together with a
# console tested against the old one. It skips only when the pinned console
# predates the copies.
#
# Run from the repository root: sh scripts/check-m3-golden-drift.sh
# LATTICE_DASHBOARD_REPO overrides where the console is fetched from (a
# local clone works).
set -eu

golden_dir="internal/server/testdata/m3-golden"
console_dir="src/testing/m3-golden"
# The lattice-dashboard commit that added the copies. A pinned ref that does
# not descend from it predates them.
copies_added="b95a4ce0e724244aefc0fc38ddd23d52c1304890"
repo="${LATTICE_DASHBOARD_REPO:-https://github.com/LatticeNet/lattice-dashboard.git}"

if [ ! -d "$golden_dir" ] || [ ! -f dashboard.ref ]; then
  echo "run from the lattice-server repository root" >&2
  exit 1
fi
ref=$(tr -d '[:space:]' < dashboard.ref)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
git -C "$work" init -q
git -C "$work" remote add origin "$repo"
# Commits only: enough to place the ref against the commit that added the
# copies. Trees and blobs are fetched on demand, the few that are read.
attempt=1
until git -C "$work" fetch -q --filter=tree:0 origin "$ref"; do
  if [ "$attempt" -ge 3 ]; then
    echo "could not fetch lattice-dashboard $ref from $repo" >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  sleep 30
done

if ! git -C "$work" merge-base --is-ancestor "$copies_added" "$ref" 2>/dev/null; then
  echo "skip: dashboard.ref $ref predates the console's golden copies (lattice-dashboard $copies_added), so there is nothing to compare"
  exit 0
fi

listing="$work/console.list"
git -C "$work" ls-tree "$ref" "$console_dir/" > "$listing"
if [ ! -s "$listing" ]; then
  echo "lattice-dashboard $ref descends from the commit that added $console_dir/ but no longer has it" >&2
  exit 1
fi

failed=0
for file in "$golden_dir"/*; do
  name=$(basename "$file")
  want=$(git hash-object "$file")
  got=$(awk -v path="$console_dir/$name" -F '\t' '$2 == path { split($1, f, " "); print f[3] }' "$listing")
  if [ -z "$got" ]; then
    echo "lattice-dashboard $ref has no $console_dir/$name" >&2
    failed=1
  elif [ "$got" != "$want" ]; then
    echo "lattice-dashboard $ref: $console_dir/$name differs from $golden_dir/$name" >&2
    git -C "$work" cat-file -p "$got" > "$work/$name"
    diff -u "$work/$name" "$file" | head -40 >&2 || true
    failed=1
  fi
done
while IFS="$(printf '\t')" read -r _ path; do
  name=$(basename "$path")
  if [ ! -f "$golden_dir/$name" ]; then
    echo "lattice-dashboard $ref has $path, which $golden_dir/ does not" >&2
    failed=1
  fi
done < "$listing"

if [ "$failed" -ne 0 ]; then
  echo "the console at dashboard.ref holds other golden responses than this server writes: copy $golden_dir/ to the console's $console_dir/ (and its GOLDEN_SERVER_COMMIT), then pin that console in dashboard.ref" >&2
  exit 1
fi
echo "m3 goldens match lattice-dashboard $ref"

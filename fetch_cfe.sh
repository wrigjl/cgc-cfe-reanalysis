#!/bin/bash
# For each CB, fetch the page and extract patch rounds + POV data
# Output: one JSON-ish line per CB with the key info

BASE="https://archive.ll.mit.edu/cgc/cgc-corpus/challenges"
HERE="$(cd "$(dirname "$0")" && pwd)"
CBLIST="$HERE/cfe-cbs.txt"
OUTDIR="$HERE/cfe-raw"
mkdir -p "$OUTDIR"

while IFS= read -r cb; do
    [ -z "$cb" ] && continue
    url="${BASE}/${cb}/"
    outfile="${OUTDIR}/${cb}.html"
    if [ ! -f "$outfile" ]; then
        curl -s -o "$outfile" "$url"
    fi
done < "$CBLIST"
echo "Done fetching $(ls "$OUTDIR" | wc -l) files"

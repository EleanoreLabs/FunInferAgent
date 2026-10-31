#!/usr/bin/env bash
# Build one evaluation binary + ground-truth pair.
#
# Usage: build_dataset.sh <unstripped_binary> <output_dir> <name>
# Produces:
#   <output_dir>/<name>.strip    stripped binary (input to FunInferAgent)
#   <output_dir>/<name>.gt.csv   ground truth "address,name" (from the symbol
#                                table BEFORE stripping)
#
# Our evaluation set was built this way from four open-source projects:
#   crypto   
#   database 
#   network  
#   video    
set -euo pipefail

BIN="$1"; OUT="$2"; NAME="$3"
mkdir -p "$OUT"

# ground truth first (needs symbols)
{
  echo "address,name"
  nm --defined-only "$BIN" | awk '{print "0x"$1","$3}'
} > "$OUT/$NAME.gt.csv"

# then strip
cp "$BIN" "$OUT/$NAME.strip"
strip --strip-all "$OUT/$NAME.strip"

echo "Wrote $OUT/$NAME.strip and $OUT/$NAME.gt.csv"

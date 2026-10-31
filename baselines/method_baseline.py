#!/usr/bin/env python3
"""Unified comparison driver for the four external baselines:
AsmDepictor, Nero, SymLM, and XFL.

This script does NOT re-implement any baseline.  It assumes the official
repositories have been cloned under ``baselines/`` and that each method has
already produced its native prediction output.  For every method this driver

  1. optionally executes a user supplied command (``--run-command``),
  2. parses the method's native prediction file,
  3. aligns the predictions to function addresses with a sidecar mapping,
  4. writes a unified ``{address: name}`` JSON (``recover_map.json``),
  5. evaluates it with the FunInferAgent evaluator ``scripts/eval_semantic.py``.

Why a sidecar is needed
-----------------------
None of the four baselines prints the function start address together with
the predicted name:

* Nero writes a CSV log whose second column is a ``package`` identifier.
* AsmDepictor writes one prediction per line, in input order.
* SymLM writes ``target,prediction,probabilities`` per line, in input order.
* XFL writes ``original => predicted`` per line.

Therefore the runner that produces the native output must also emit an
"address sidecar".  Two sidecar shapes are accepted (JSON):

1. A list, for order preserving methods::

       ["0x401000", "0x401120", ...]

   or a list of objects::

       [{"address": "0x401000"}, {"address": "0x401120"}, ...]

2. A dict, for methods that can be keyed by a native identifier::

       {"<package-or-original-name>": "0x401000", ...}

   For order preserving methods a dict with numeric keys is also accepted::

       {"0": "0x401000", "1": "0x401120", ...}

Examples
--------
Evaluate a single method::

    python baselines/method_baseline.py \
        --method symlm \
        --gt dataset/crypto/openssl.gt.csv \
        --prediction baselines/SymLM-main/SymLM-main/training_evaluation/prediction_evaluation/evaluation_input.txt \
        --sidecar  work/symlm/address_sidecar.json \
        --output   work/symlm/recover_map.json \
        --threshold 80

Evaluate all four methods when the work directory uses one folder per method
(``{method}`` is expanded for every method)::

    python baselines/method_baseline.py \
        --method all \
        --gt dataset/crypto/openssl.gt.csv \
        --prediction work/{method}/prediction.txt \
        --sidecar    work/{method}/address_sidecar.json \
        --output     work/{method}/recover_map.json

Only parse a native output file (no evaluation)::

    python baselines/method_baseline.py \
        --method nero \
        --prediction work/nero/models_9999_log.txt \
        --sidecar    work/nero/address_sidecar.json \
        --output     work/nero/recover_map.json

Notes
-----
* ``--threshold`` is forwarded to ``scripts/eval_semantic.py`` through the
  ``THRESHOLD`` environment variable (``0`` = token based, ``>0`` = LLM judge).
* The evaluation itself is exactly the FunInferAgent evaluation; no metric is
  reimplemented here.
* Coverage (``gt_total``, ``pred_total``, ``matched``) is reported separately
  because the evaluator only scores the address intersection.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Repository layout
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent
EVAL_SCRIPT = REPO_ROOT / "scripts" / "eval_semantic.py"

METHODS: Tuple[str, ...] = ("asmdepictor", "nero", "symlm", "xfl")

METHOD_HOME = {
    "asmdepictor": BASE_DIR / "AsmDepictor-main" / "AsmDepictor-main",
    "nero": BASE_DIR / "Nero-main" / "Nero-main",
    "symlm": BASE_DIR / "SymLM-main" / "SymLM-main",
    # XFL-R is the maintained/refactored version and the recommended one.
    "xfl": BASE_DIR / "xfl-main" / "xfl-main" / "xfl-r" / "XFL",
}

# Keys that are searched (in this order) when a sidecar entry is a dict.
_ADDRESS_KEYS: Tuple[str, ...] = (
    "address",
    "addr",
    "start",
    "start_ea",
    "startEA",
    "vaddr",
    "function_address",
    "func_addr",
)

# Marker that can be injected into Nero's ``package`` field to carry the
# function start address through the whole Nero pipeline.
NERO_ADDR_MARKER = "__FUNINFER_ADDR__"
NERO_ADDR_RE = re.compile(NERO_ADDR_MARKER + r"(0x[0-9a-fA-F]+)")

# SymLM's official evaluation threshold (see training_evaluation/evaluation.py).
SYMLM_PROBABILITY_THRESHOLD = 0.3


# ---------------------------------------------------------------------------
# Address / sidecar helpers
# ---------------------------------------------------------------------------

def normalize_address(value: Any, address_base: int = 16) -> Optional[str]:
    """Return ``hex(int(value, address_base))`` or ``None`` on failure."""
    if value is None:
        return None
    if isinstance(value, bool):  # bool is an int subclass; reject it explicitly
        return None
    if isinstance(value, int):
        return hex(value)
    text = str(value).strip()
    if not text:
        return None
    # ``int("0x401000", 16)`` works, ``int("0x401000", 10)`` does not.
    base = 16 if text.lower().startswith("0x") else address_base
    try:
        return hex(int(text, base))
    except ValueError:
        return None


def _address_from_sidecar_item(item: Any, address_base: int) -> Optional[str]:
    if isinstance(item, dict):
        for key in _ADDRESS_KEYS:
            if key in item:
                return normalize_address(item[key], address_base)
        return None
    return normalize_address(item, address_base)


def load_sidecar(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def ordered_addresses_from_sidecar(
    sidecar: Any,
    expected_count: Optional[int] = None,
    address_base: int = 16,
) -> List[str]:
    """Interpret a sidecar as an ordered list of addresses.

    * list  -> one address per entry (plain value or dict)
    * dict  -> numeric keys are interpreted as line indices
    """
    addresses: List[str] = []

    if isinstance(sidecar, list):
        for item in sidecar:
            address = _address_from_sidecar_item(item, address_base)
            if address is None:
                raise ValueError(f"Sidecar list entry is not an address: {item!r}")
            addresses.append(address)
    elif isinstance(sidecar, dict):
        keys = list(sidecar.keys())
        if not all(isinstance(key, str) and key.isdigit() for key in keys):
            raise ValueError(
                "Ordered sidecar must be a list, or a dict with numeric keys "
                "(line index -> address)"
            )
        for key in sorted(keys, key=int):
            address = normalize_address(sidecar[key], address_base)
            if address is None:
                raise ValueError(f"Sidecar entry for line {key} is not an address")
            addresses.append(address)
    else:
        raise ValueError("Sidecar must be a JSON list or object")

    if expected_count is not None and len(addresses) != expected_count:
        raise ValueError(
            f"Sidecar has {len(addresses)} addresses but the native output has "
            f"{expected_count} lines"
        )
    return addresses


def mapping_from_sidecar(
    sidecar: Any,
    address_base: int = 16,
) -> Dict[str, str]:
    """Interpret a sidecar as ``{native identifier: address}``.

    Accepted shapes:

    * ``{"<package>": "0x401000", ...}``
    * ``[{"package": "...", "address": "0x401000"}, ...]``
    * ``[{"name": "...", "address": "0x401000"}, ...]`` (used by XFL)
    """
    mapping: Dict[str, str] = {}

    if isinstance(sidecar, dict):
        for key, value in sidecar.items():
            address = normalize_address(value, address_base)
            if address is None:
                raise ValueError(f"Sidecar value for key {key!r} is not an address")
            mapping[str(key)] = address
        return mapping

    if isinstance(sidecar, list):
        for item in sidecar:
            if not isinstance(item, dict):
                continue
            address = _address_from_sidecar_item(item, address_base)
            if address is None:
                continue
            key = None
            for candidate in ("package", "name", "original", "original_name", "key", "id"):
                if candidate in item:
                    key = item[candidate]
                    break
            if key is None:
                continue
            mapping[str(key)] = address
        if not mapping:
            raise ValueError(
                "Sidecar list does not contain {package/name/original, address} objects"
            )
        return mapping

    raise ValueError("Sidecar must be a JSON list or object")


# ---------------------------------------------------------------------------
# Native parsers
# ---------------------------------------------------------------------------

def parse_nero_log(
    prediction_path: Path,
    sidecar: Optional[Any],
    address_base: int = 16,
) -> Tuple[Dict[str, str], Dict[str, int]]:
    """Parse Nero's ``*_9999_log.txt``.

    Expected columns: ``PredCode,package,Original,Predicted,Thrown``.
    The address is taken from (in order of preference):

    1. an injected ``__FUNINFER_ADDR__0x...`` marker inside ``package``,
    2. a sidecar mapping keyed by the full ``package`` string,
    3. a sidecar mapping keyed by the original sub-token name,
    4. an ordered sidecar (line index -> address).
    """
    mapping: Dict[str, str] = {}
    if sidecar is not None:
        try:
            mapping = mapping_from_sidecar(sidecar, address_base)
        except ValueError:
            mapping = {}

    lines = prediction_path.read_text(encoding="utf-8", errors="replace").splitlines()
    ordered: Optional[List[str]] = None
    if sidecar is not None and not mapping:
        ordered = ordered_addresses_from_sidecar(sidecar, len(lines), address_base)

    results: Dict[str, str] = {}
    stats = {
        "rows": 0,
        "mapped": 0,
        "unmapped": 0,
        "empty_predictions": 0,
    }

    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        if line.startswith("PredCode,"):
            continue

        parts = line.split(",", 4)
        if len(parts) < 5:
            stats["unmapped"] += 1
            continue
        _pred_code, package, original, predicted, _thrown = parts
        stats["rows"] += 1

        address: Optional[str] = None
        marker = NERO_ADDR_RE.search(package)
        if marker:
            address = normalize_address(marker.group(1), 16)
        if address is None:
            address = mapping.get(package)
        if address is None:
            address = mapping.get(original)
        if address is None and ordered is not None:
            index = line_number - 2 if lines and lines[0].startswith("PredCode,") else line_number - 1
            if 0 <= index < len(ordered):
                address = ordered[index]

        if address is None:
            stats["unmapped"] += 1
            continue

        # Nero separates sub-tokens with ``*``; the unified map uses ``_``.
        name = predicted.strip().replace("*", "_")
        if not name:
            stats["empty_predictions"] += 1
        results[address] = name
        stats["mapped"] += 1

    return results, stats


def parse_asmdepictor_predictions(
    prediction_path: Path,
    sidecar: Optional[Any],
    address_base: int = 16,
) -> Tuple[Dict[str, str], Dict[str, int]]:
    """Parse AsmDepictor's ``predicted_output/prediction.txt``.

    The file contains one predicted name per line, in the same order as the
    test JSONL.  Addresses therefore must come from an ordered sidecar.
    """
    lines = prediction_path.read_text(encoding="utf-8", errors="replace").splitlines()
    if sidecar is None:
        raise ValueError("AsmDepictor requires an ordered address sidecar")

    addresses = ordered_addresses_from_sidecar(sidecar, len(lines), address_base)

    results: Dict[str, str] = {}
    stats = {
        "rows": len(lines),
        "mapped": len(lines),
        "unmapped": 0,
        "empty_predictions": 0,
    }

    for address, line in zip(addresses, lines):
        tokens = line.split()
        name = "_".join(tokens)
        if not name:
            stats["empty_predictions"] += 1
        results[address] = name

    return results, stats


def parse_symlm_evaluation_input(
    prediction_path: Path,
    sidecar: Optional[Any],
    address_base: int = 16,
    probability_threshold: float = SYMLM_PROBABILITY_THRESHOLD,
) -> Tuple[Dict[str, str], Dict[str, int]]:
    """Parse SymLM's ``evaluation_input.txt``.

    Every line has the shape::

        <target words>,<top-10 predicted words>,[p0 p1 ... p9]

    The official post-processing keeps every word with
    ``probability >= 0.3``; if no word passes the threshold the single most
    probable word is used.  Addresses must come from an ordered sidecar and
    SymLM must be run with ``--no-shuffle`` so the order is preserved.
    """
    lines = prediction_path.read_text(encoding="utf-8", errors="replace").splitlines()
    if sidecar is None:
        raise ValueError("SymLM requires an ordered address sidecar")

    addresses = ordered_addresses_from_sidecar(sidecar, len(lines), address_base)

    results: Dict[str, str] = {}
    stats = {
        "rows": len(lines),
        "mapped": len(lines),
        "unmapped": 0,
        "empty_predictions": 0,
        "threshold_fallbacks": 0,
        "malformed_lines": 0,
    }

    for address, line in zip(addresses, lines):
        parts = line.split(",", 2)
        if len(parts) != 3:
            stats["malformed_lines"] += 1
            results[address] = ""
            continue

        _target, words_text, probabilities_text = parts
        words = words_text.split()
        cleaned = probabilities_text.strip().lstrip("[").rstrip("]")
        try:
            probabilities = [float(value) for value in cleaned.split()]
        except ValueError:
            probabilities = []

        if not words or not probabilities:
            stats["empty_predictions"] += 1
            results[address] = ""
            continue

        pairs = list(zip(words, probabilities))
        selected = [word for word, probability in pairs
                    if probability >= probability_threshold]
        if not selected:
            selected = [pairs[0][0]]
            stats["threshold_fallbacks"] += 1

        name = "_".join(selected)
        if not name:
            stats["empty_predictions"] += 1
        results[address] = name

    return results, stats


def parse_xfl_log(
    prediction_path: Path,
    sidecar: Optional[Any],
    address_base: int = 16,
) -> Tuple[Dict[str, str], Dict[str, int]]:
    """Parse XFL's ``deduction.log`` / ``*.log``.

    Every line has the shape::

        <original function name> => <predicted function name>

    Addresses are resolved from a sidecar mapping the original function name
    to its start address.  An ordered sidecar (one address per line) is also
    supported, but is only correct when the log order is guaranteed.
    """
    mapping: Dict[str, str] = {}
    ordered: Optional[List[str]] = None

    if sidecar is not None:
        try:
            mapping = mapping_from_sidecar(sidecar, address_base)
        except ValueError:
            mapping = {}

    lines = prediction_path.read_text(encoding="utf-8", errors="replace").splitlines()

    if sidecar is not None and not mapping:
        ordered = ordered_addresses_from_sidecar(sidecar, len(lines), address_base)

    results: Dict[str, str] = {}
    stats = {
        "rows": 0,
        "mapped": 0,
        "unmapped": 0,
        "empty_predictions": 0,
    }

    for line_number, line in enumerate(lines, start=1):
        if "=>" not in line:
            continue
        original, predicted = line.split("=>", 1)
        original = original.strip()
        predicted = predicted.strip()
        stats["rows"] += 1

        address: Optional[str] = mapping.get(original)
        if address is None and ordered is not None:
            index = line_number - 1
            if 0 <= index < len(ordered):
                address = ordered[index]
        if address is None:
            stats["unmapped"] += 1
            continue

        if not predicted:
            stats["empty_predictions"] += 1
        results[address] = predicted
        stats["mapped"] += 1

    return results, stats


PARSERS = {
    "asmdepictor": parse_asmdepictor_predictions,
    "nero": parse_nero_log,
    "symlm": parse_symlm_evaluation_input,
    "xfl": parse_xfl_log,
}


# ---------------------------------------------------------------------------
# Ground truth / evaluation helpers
# ---------------------------------------------------------------------------

def load_gt_addresses(gt_path: Path, address_base: int = 16) -> set:
    """Read the ``address,name`` ground-truth CSV and return the address set."""
    addresses = set()
    with open(gt_path, "r", newline="", encoding="utf-8") as handle:
        first_line = handle.readline()
        handle.seek(0)
        if first_line.lower().startswith("address"):
            reader = csv.DictReader(handle)
            for row in reader:
                address = normalize_address(row.get("address"), address_base)
                if address is not None:
                    addresses.add(address)
        else:
            reader = csv.reader(handle)
            for row in reader:
                if not row:
                    continue
                address = normalize_address(row[0], address_base)
                if address is not None:
                    addresses.add(address)
    return addresses


def coverage_stats(predictions: Dict[str, str], gt_addresses: set) -> Dict[str, int]:
    predicted = set(predictions)
    matched = predicted & gt_addresses
    return {
        "gt_total": len(gt_addresses),
        "pred_total": len(predicted),
        "matched": len(matched),
        "missing": len(gt_addresses - predicted),
        "extra": len(predicted - gt_addresses),
    }


def write_recover_map(predictions: Dict[str, str], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(predictions, handle, indent=2, sort_keys=True)
        handle.write("\n")


def run_eval_semantic(
    gt_path: Path,
    recover_map_path: Path,
    threshold: Optional[int] = None,
) -> int:
    command = [sys.executable, str(EVAL_SCRIPT), str(gt_path), str(recover_map_path)]
    environment = os.environ.copy()
    if threshold is not None:
        environment["THRESHOLD"] = str(threshold)
    result = subprocess.run(command, env=environment)
    return result.returncode


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def expand_method_placeholder(value: Optional[str], method: str) -> Optional[str]:
    if value is None:
        return None
    return value.replace("{method}", method)


def parse_method_list(value: str) -> List[str]:
    if value.lower() == "all":
        return list(METHODS)
    requested = [item.strip().lower() for item in value.split(",") if item.strip()]
    unknown = [item for item in requested if item not in METHODS]
    if unknown:
        raise argparse.ArgumentTypeError(
            f"Unknown method(s): {', '.join(unknown)}. Choose from {', '.join(METHODS)} or 'all'."
        )
    return requested


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compare AsmDepictor / Nero / SymLM / XFL against the FunInferAgent "
            "evaluation. The script parses each method's native prediction file, "
            "aligns it to function addresses with a sidecar, and runs "
            "scripts/eval_semantic.py."
        )
    )
    parser.add_argument(
        "--method",
        type=parse_method_list,
        default=list(METHODS),
        help=(
            "One of asmdepictor, nero, symlm, xfl; a comma separated list; or 'all'. "
            "Paths may contain the {method} placeholder."
        ),
    )
    parser.add_argument(
        "--gt",
        type=Path,
        help="Ground-truth CSV (address,name). If omitted, only parsing is performed.",
    )
    parser.add_argument(
        "--prediction",
        type=Path,
        required=True,
        help=(
            "Native prediction file of the selected method. "
            "The {method} placeholder is expanded."
        ),
    )
    parser.add_argument(
        "--sidecar",
        type=Path,
        help=(
            "JSON address sidecar (ordered list or identifier->address mapping). "
            "Required for AsmDepictor and SymLM; recommended for Nero and XFL. "
            "The {method} placeholder is expanded."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        help=(
            "Where to write the unified {address: name} recover map. "
            "Defaults to <prediction>.recover_map.json. "
            "The {method} placeholder is expanded."
        ),
    )
    parser.add_argument(
        "--run-command",
        help=(
            "Optional shell command executed in the method's repository before parsing. "
            "Use it to launch the official pipeline. The {method} placeholder is expanded."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the commands and resolved paths without running anything.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        help=(
            "Forwarded to scripts/eval_semantic.py as THRESHOLD "
            "(0 = token based CodeWordNet-LLM, >0 = score based LLM judge)."
        ),
    )
    parser.add_argument(
        "--address-base",
        type=int,
        choices=(10, 16),
        default=16,
        help="Base used for sidecar/GT address strings without a 0x prefix (default: 16).",
    )
    parser.add_argument(
        "--symlm-probability-threshold",
        type=float,
        default=SYMLM_PROBABILITY_THRESHOLD,
        help="SymLM probability threshold used to select predicted words (default: 0.3).",
    )
    parser.add_argument(
        "--skip-missing",
        action="store_true",
        help="Skip a method when its prediction or sidecar file does not exist.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    overall_returncode = 0

    for method in args.method:
        print(f"\n=== {method.upper()} ===")

        prediction_raw = expand_method_placeholder(str(args.prediction), method)
        sidecar_raw = expand_method_placeholder(str(args.sidecar), method) if args.sidecar else None
        output_raw = expand_method_placeholder(str(args.output), method) if args.output else None
        run_command = expand_method_placeholder(args.run_command, method) if args.run_command else None

        prediction_path = Path(prediction_raw)
        sidecar_path = Path(sidecar_raw) if sidecar_raw else None
        output_path = Path(output_raw) if output_raw else prediction_path.with_suffix(
            prediction_path.suffix + ".recover_map.json"
        )

        print(f"prediction : {prediction_path}")
        print(f"sidecar    : {sidecar_path}")
        print(f"output     : {output_path}")

        if args.dry_run:
            if run_command:
                home = METHOD_HOME[method]
                print(f"run command: {run_command}")
                print(f"cwd        : {home}")
            print("dry-run: nothing executed")
            continue

        if not prediction_path.exists():
            if args.skip_missing:
                print(f"WARNING: prediction file missing, skipping {method}")
                continue
            print(f"ERROR: prediction file does not exist: {prediction_path}")
            overall_returncode = 1
            continue

        if sidecar_path is not None and not sidecar_path.exists():
            if args.skip_missing:
                print(f"WARNING: sidecar file missing, skipping {method}")
                continue
            print(f"ERROR: sidecar file does not exist: {sidecar_path}")
            overall_returncode = 1
            continue

        if run_command:
            home = METHOD_HOME.get(method)
            if home is None or not home.exists():
                print(f"ERROR: repository for {method} not found: {home}")
                overall_returncode = 1
                continue
            print(f"running   : {run_command}")
            print(f"cwd       : {home}")
            result = subprocess.run(run_command, shell=True, cwd=str(home))
            if result.returncode != 0:
                print(f"ERROR: {method} command failed with code {result.returncode}")
                overall_returncode = 1
                continue
            if not prediction_path.exists():
                print(f"ERROR: command finished but prediction file is missing: {prediction_path}")
                overall_returncode = 1
                continue

        sidecar = load_sidecar(sidecar_path) if sidecar_path is not None else None

        try:
            if method == "symlm":
                predictions, stats = parse_symlm_evaluation_input(
                    prediction_path,
                    sidecar,
                    address_base=args.address_base,
                    probability_threshold=args.symlm_probability_threshold,
                )
            else:
                parser_function = PARSERS[method]
                predictions, stats = parser_function(
                    prediction_path,
                    sidecar,
                    address_base=args.address_base,
                )
        except Exception as error:  # keep the loop running for the other methods
            print(f"ERROR: failed to parse {method} output: {error}")
            overall_returncode = 1
            continue

        print("parse stats:")
        for key, value in stats.items():
            print(f"  {key:20} {value}")

        write_recover_map(predictions, output_path)
        print(f"recover map: {output_path} ({len(predictions)} functions)")

        if args.gt is None:
            continue

        if not args.gt.exists():
            print(f"ERROR: ground-truth file does not exist: {args.gt}")
            overall_returncode = 1
            continue

        gt_addresses = load_gt_addresses(args.gt, address_base=args.address_base)
        coverage = coverage_stats(predictions, gt_addresses)
        print("coverage:")
        for key, value in coverage.items():
            print(f"  {key:10} {value}")

        returncode = run_eval_semantic(args.gt, output_path, threshold=args.threshold)
        if returncode != 0:
            print(f"ERROR: evaluation failed for {method} (code {returncode})")
            overall_returncode = 1

    return overall_returncode


if __name__ == "__main__":
    raise SystemExit(main())

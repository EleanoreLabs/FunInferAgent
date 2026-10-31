"""FunInferPipeline: layer-by-layer bidirectional BFS over the call graph.

This is the module imported by `main_ida_pipeline.py`. Requires IDAPython —
run inside IDA (idat64).

Pipeline (one function per step):
  1. Seed the queue with the leaf ("bottom") functions of the call graph.
  2. For each function, assemble its three semantic sources:
       S1 — callee summaries: one-line LLM summaries of already-processed
            sub-functions, injected as comments;
       S2 — local body: the function's own Hex-Rays decompiled code;
       S3 — parent contexts: sliding-window decompiled snippets around the
            call sites of this function in its callers.
  3. Query the LLM for a name (rename in the IDB) and a summary; the summary
     is backtracked against the parent contexts and stored for later callers.
  4. Callers discovered through code xrefs enter a secondary queue and are
     promoted layer by layer, so callees are always named before callers.

Ablations (Config.ABLATION, set via FUNINFER_ABLATION):
  wo_s1: drop callee summaries        (no S1 comments injected)
  wo_s2: drop local decompiled code   (name from S1+S3 only)
  wo_s3: drop parent call contexts    (parent_params = None)
"""
import idautils
import idc
import ida_hexrays
import idaapi
import logging

from funinfer.config import Config
from funinfer.extraction.ida_analyzer import IDAAnalyzer
from funinfer.semantics.llm_client import LLMClient

logger = logging.getLogger(__name__)


class FunInferPipeline:
    def __init__(self):
        self.analyzer = IDAAnalyzer()
        self.llm = LLMClient()
        # Ablation switch: "" (full) | "wo_s1" | "wo_s2" | "wo_s3"
        self.ablation = Config.ABLATION
        if self.ablation:
            logger.info(f"Ablation mode: {self.ablation}")

    # ---------- semantic source assembly ----------

    def _build_body(self, item, summary_dict) -> str:
        """S2 (local decompiled code) with S1 (callee summaries) injected as
        comments. Ablations: wo_s2 removes the body, wo_s1 removes the
        injected summaries."""
        if self.ablation == "wo_s2":
            # Name from S1+S3 only: still inject the callee summaries.
            decompiler_output = ""
        else:
            try:
                cfunc = ida_hexrays.decompile(item)
            except Exception as e:
                logger.warning(f"Decompile failed for {hex(item)}: {e}")
                return ""
            if cfunc is None:
                return ""
            decompiler_output = str(cfunc) + '\n'

        if self.ablation != "wo_s1":
            for called in self.analyzer.get_called_functions(item):
                if called in summary_dict:
                    decompiler_output += \
                        f'// {idaapi.get_name(called)}: {summary_dict[called]}\n'
        return decompiler_output

    def _build_parent_params(self, item) -> dict:
        """S3 — parent call contexts. Ablation wo_s3: drop them entirely."""
        if self.ablation == "wo_s3":
            return None
        return self.analyzer.get_parent_function_params(item)

    # ---------- main loop ----------

    def run(self):
        bottom_funcs = self.analyzer.get_bottom_functions()
        queue = [f['address'] for f in bottom_funcs]
        # Bottom functions without any library anchor are "pure body"
        # computations: use the dedicated prompt variant for them.
        pure_body = {f['address'] for f in bottom_funcs
                     if not f.get('has_lib_anchor', False)}
        finished = set()
        summary_dict = {}
        secondary_queue = []
        layer = 0

        while queue or secondary_queue:
            if not queue:
                layer += 1
                logger.info(f"Processing layer {layer}")
                queue, secondary_queue = \
                    self._promote_secondary_queue(secondary_queue)
                if not queue:
                    # No caller is ready (cyclic region): take one anyway so
                    # the pipeline cannot stall.
                    queue = [secondary_queue.pop(0)] if secondary_queue else []

            item = queue.pop(0)
            logger.info(f"Processing {hex(item)}")

            parent_params = self._build_parent_params(item)
            is_pure = item in pure_body
            decompiler_output = self._build_body(item, summary_dict)

            if not decompiler_output and not parent_params:
                # Nothing to ground a name on — still record the function as
                # processed so callers are not blocked on it.
                logger.warning(f"Skip {hex(item)}: no semantic sources")
                finished.add(item)
                self._update_queues(item, queue, secondary_queue, finished)
                continue

            new_names = self.llm.query_name(decompiler_output, parent_params,
                                            is_pure)
            # Echo the RAW LLM answer into the pipeline log: the address is
            # authoritative (the `Processing` line above), and
            # scripts/parse_rename_log.py recovers both JSON forms from
            # this dict line.
            print(new_names)
            self.analyzer.rename_to_ida(item, new_names)

            current_summary = self.llm.query_summary(decompiler_output,
                                                     parent_params, is_pure)
            if current_summary:
                summary_dict[item] = self._enhance_semantics(current_summary,
                                                             parent_params)

            finished.add(item)
            self._update_queues(item, queue, secondary_queue, finished)

    def _enhance_semantics(self, summary: str, parent_params: dict) -> str:
        """Backtracking: fold how the parents use the function into its
        summary, so later callers receive callee-side usage evidence."""
        if not parent_params:
            return summary
        try:
            enhanced = self.llm.enhance_summary(summary, parent_params)
            if enhanced:
                return enhanced
        except Exception as e:
            logger.warning(f"Summary enhancement failed: {e}")
        return f"{summary}\n[Contexts from {len(parent_params)} parent functions]"

    # ---------- queue scheduling ----------

    def _promote_secondary_queue(self, secondary_queue: list) -> tuple:
        """Promote waiting callers, fewest unfinished dependencies first.

        Returns (promoted, remaining): promoted functions join the main queue
        now; the rest stay in the secondary queue for the next layer, so each
        layer is named on top of an already-named layer.
        """
        if not secondary_queue:
            return [], []
        waiting = set(secondary_queue)
        deps = {}
        for addr in secondary_queue:
            callees = self.analyzer.get_called_functions(addr)
            deps[addr] = sum(1 for c in callees if c in waiting and c != addr)
        min_dep = min(deps.values())
        promoted = [addr for addr, n in deps.items() if n == min_dep]
        remaining = [addr for addr in secondary_queue if addr not in set(promoted)]
        return promoted, remaining

    def _update_queues(self, item, queue, secondary_queue, finished):
        """Enqueue the not-yet-processed callers of `item`."""
        for ref in idautils.CodeRefsTo(item, 0):
            func_start = idc.get_func_attr(ref, idc.FUNCATTR_START)
            if (func_start != 0xFFFFFFFFFFFFFFFF and
                    func_start not in queue and
                    func_start not in finished and
                    func_start not in secondary_queue and
                    idc.get_segm_name(func_start) not in Config.BYPASS_SECTIONS):
                secondary_queue.append(func_start)

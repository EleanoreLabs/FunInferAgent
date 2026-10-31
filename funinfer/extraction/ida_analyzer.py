"""IDA-side analysis helpers: function discovery, call-graph queries, renaming."""
import logging
import re

import idaapi
import idautils
import idc
import ida_hexrays

from funinfer.config import Config
from funinfer.extraction.context_parser import ContextParser

logger = logging.getLogger(__name__)


class IDAAnalyzer:
    @staticmethod
    def get_bottom_functions() -> list:
        """Leaf functions of the program's own call graph.

        A function is 'bottom' if it has no code xref to another function in
        `.text` (indirect calls included, via XrefsFrom). Each entry also
        carries `has_lib_anchor`: True if the function calls into bypassed
        sections (.plt, extern, ...), i.e. it has a visible library/API
        anchor the LLM can ground names on.
        """
        bottom_functions = []
        for func_ea in idautils.Functions():
            if idc.get_segm_name(func_ea) in Config.BYPASS_SECTIONS:
                continue

            func_name = idc.get_func_name(func_ea)
            is_bottom = True
            has_lib_anchor = False

            for ea in idautils.FuncItems(func_ea):
                for xref in idautils.XrefsFrom(ea, 0):
                    if xref.type in (idaapi.fl_CN, idaapi.fl_CF):
                        target_func = idaapi.get_func(xref.to)
                        if target_func:
                            seg_name = idc.get_segm_name(target_func.start_ea)
                            if seg_name == ".text" and target_func.start_ea != func_ea:
                                is_bottom = False
                                break
                            elif seg_name in Config.BYPASS_SECTIONS:
                                has_lib_anchor = True
                if not is_bottom:
                    break

            if is_bottom:
                bottom_functions.append({
                    "address": func_ea,
                    "name": func_name,
                    "has_lib_anchor": has_lib_anchor,
                })
        return bottom_functions

    @staticmethod
    def get_called_functions(func_ea) -> set:
        called = set()
        for ea in idautils.FuncItems(func_ea):
            for xref in idautils.XrefsFrom(ea, 0):
                if xref.type in (idaapi.fl_CN, idaapi.fl_CF):
                    target_func = idaapi.get_func(xref.to)
                    if target_func:
                        called.add(target_func.start_ea)
        return called

    @staticmethod
    def get_parent_function_params(func_ea) -> dict:
        """Caller contexts, truncated to Config.MAX_CONTEXT_COUNT entries to
        bound prompt tokens."""
        parent_params = {}
        context_count = 0

        for xref in idautils.XrefsTo(func_ea, 0):
            if xref.type == idaapi.fl_CN:
                if context_count >= Config.MAX_CONTEXT_COUNT:
                    logger.info(
                        f"[Truncated] Max parent contexts "
                        f"({Config.MAX_CONTEXT_COUNT}) reached for {hex(func_ea)}")
                    break

                ctx_code = ContextParser.decompile_window_around_statement(
                    xref.frm, Config.CONTEXT_WINDOW_SIZE)
                if ctx_code:
                    parent_func = idaapi.get_func(xref.frm)
                    if parent_func:
                        parent_name = idaapi.get_name(parent_func.start_ea)
                        if parent_name not in parent_params:
                            parent_params[parent_name] = []
                        parent_params[parent_name].append({
                            'call_address': hex(xref.frm),
                            'context': ctx_code
                        })
                        context_count += 1
        return parent_params

    @staticmethod
    def rename_to_ida(address, names):
        """Apply LLM-proposed names back into the IDB.

        Accepts both JSON forms the LLM may return:
          form a: {"sub_401000": "parse_cfg"}           (key = current name)
          form b: {"old_name": "sub_401000", "new_name": "parse_cfg"}
        The address is authoritative, so the proposed name is applied to this
        function regardless of whether the LLM echoed the old name correctly.
        """
        if not names:
            return
        func_ea = idaapi.get_func(address).start_ea
        old_name = idaapi.get_name(func_ea)

        new_name = None
        if isinstance(names, dict):
            if 'new_name' in names and 'old_name' in names:
                new_name = names['new_name']
            elif old_name in names:
                new_name = names[old_name]
            elif len(names) == 1:
                new_name = next(iter(names.values()))

        if isinstance(new_name, str) and new_name and old_name.startswith('sub_'):
            idaapi.set_name(func_ea, new_name, idaapi.SN_FORCE)

        # Local-variable renames: only for keys that look like real lvar names
        # (skip the function-name key and the form-b meta keys).
        replaced = []
        for n in names:
            if n in ('old_name', 'new_name') or n == old_name:
                continue
            try:
                v = names[n]
                if not isinstance(v, str):
                    continue
                if ida_hexrays.rename_lvar(func_ea, n, v):
                    replaced.append(n)
            except Exception as e:
                logger.warning(f"Rename error: {e}")

        comment = idc.get_func_cmt(address, 0)
        if comment and replaced:
            for n in replaced:
                comment = re.sub(r'\b%s\b' % re.escape(n), names[n], comment)
            idc.set_func_cmt(address, comment, 0)

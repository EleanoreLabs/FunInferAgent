import idaapi
import idautils
import idc
import ida_hexrays
import re
from funinfer.config import Config
from funinfer.extraction.context_parser import ContextParser

class IDAAnalyzer:
    @staticmethod
    def get_bottom_functions() -> list:
        bottom_functions = []
        for func_ea in idautils.Functions():
            if idc.get_segm_name(func_ea) in Config.BYPASS_SECTIONS:
                continue

            func_name = idc.get_func_name(func_ea)
            is_bottom = True

            for head in idautils.FuncItems(func_ea):
                if idc.print_insn_mnem(head) in ("call", "BL", "BLX"):
                    target = idc.get_operand_value(head, 0)
                    if target != idc.BADADDR and idc.get_segm_name(target) == ".text":
                        called_func = idc.get_func_name(target)
                        if called_func and called_func != func_name:
                            is_bottom = False
                            break

            if is_bottom:
                bottom_functions.append({"address": func_ea, "name": func_name})
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
        parent_params = {}
        for xref in idautils.XrefsTo(func_ea, 0):
            if xref.type == idaapi.fl_CN:
                ctx_code = ContextParser.decompile_window_around_statement(xref.frm, Config.CONTEXT_WINDOW_SIZE)
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
        return parent_params

    @staticmethod
    def rename_to_ida(address, names):
        func_ea = idaapi.get_func(address).start_ea
        old_name = idaapi.get_name(func_ea)
        
        if old_name.startswith('sub_') and old_name in names:
            idaapi.set_name(func_ea, names[old_name], idaapi.SN_FORCE)

        replaced = []
        for n in names:
            try:
                if ida_hexrays.rename_lvar(func_ea, n, names[n]):
                    replaced.append(n)
            except Exception as e:
                pass 

        comment = idc.get_func_cmt(address, 0)
        if comment and replaced:
            for n in replaced:
                comment = re.sub(r'\b%s\b' % n, names[n], comment)
            idc.set_func_cmt(address, comment, 0)
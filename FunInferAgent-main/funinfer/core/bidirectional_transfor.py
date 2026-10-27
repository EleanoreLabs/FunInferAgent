import idautils
import idc
import ida_hexrays
import idaapi
import logging
from funinfer.extraction.ida_analyzer import IDAAnalyzer
from funinfer.semantics.llm_client import LLMClient
from funinfer.config import Config

logger = logging.getLogger(__name__)

class FunInferPipeline:
    def __init__(self):
        self.analyzer = IDAAnalyzer()
        self.llm = LLMClient()

    def run(self):
        bottom_funcs = self.analyzer.get_bottom_functions()
        queue = [f['address'] for f in bottom_funcs]
        finished = set()
        summary_dict = {}
        secondary_queue = []
        layer = 0

        while queue or secondary_queue:
            if not queue:
                layer += 1
                logger.info(f"Processing layer {layer}")
                queue = self._promote_secondary_queue(secondary_queue)
                secondary_queue = []

            item = queue.pop(0)
            logger.info(f"Processing {hex(item)}")

            parent_params = self.analyzer.get_parent_function_params(item)
            
            decompiler_output = str(ida_hexrays.decompile(item)) + '\n'
            for called in self.analyzer.get_called_functions(item):
                if called in summary_dict:
                    decompiler_output += f'// {idaapi.get_name(called)}: {summary_dict[called]}\n'

            new_names = self.llm.query_name(decompiler_output, parent_params)
            self.analyzer.rename_to_ida(item, new_names)

            current_summary = self.llm.query_summary(decompiler_output, parent_params)
            if current_summary:
                summary_dict[item] = self._enhance_semantics(current_summary, parent_params)

            finished.add(item)
            self._update_queues(item, queue, secondary_queue, finished)

    def _enhance_semantics(self, summary: str, parent_params: dict) -> str:
        if not parent_params:
            return summary
        return f"{summary}\n[Contexts from {len(parent_params)} parent functions]"

    def _promote_secondary_queue(self, secondary_queue: list) -> list:
        first_queue = []
        while secondary_queue:
            tmp_dict = {addr: 0 for addr in secondary_queue}
            for addr in secondary_queue:
                for ref in idautils.CodeRefsTo(addr, 0):
                    func_start = idc.get_func_attr(ref, idc.FUNCATTR_START)
                    if func_start != 0xFFFFFFFFFFFFFFFF and idc.get_segm_name(func_start) not in Config.BYPASS_SECTIONS:
                        if func_start in second_queue:
                            tmp_dict[func_start] += 1
                            
            if not tmp_dict:
                break
                
            min_xref = min(tmp_dict.values())
            secondary_queue = []
            for k, v in tmp_dict.items():
                if v == min_xref:
                    first_queue.append(k)
                else:
                    secondary_queue.append(k)
        return first_queue

    def _update_queues(self, item, queue, secondary_queue, finished):
        for ref in idautils.CodeRefsTo(item, 0):
            func_start = idc.get_func_attr(ref, idc.FUNCATTR_START)
            if (func_start != 0xFFFFFFFFFFFFFFFF and 
                func_start not in queue and 
                func_start not in finished and
                idc.get_segm_name(func_start) not in Config.BYPASS_SECTIONS):
                secondary_queue.append(func_start)
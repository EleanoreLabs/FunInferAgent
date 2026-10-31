"""Extraction of decompiled-code context windows around call sites."""
import idaapi


class ContextParser:
    """Sliding-window reader over Hex-Rays pseudocode.

    Given the address of a call instruction inside a function, return the
    decompiled lines surrounding that call site (the "dynamic sliding
    window" of the paper): `window_size` lines before and after the line
    that contains the call.
    """

    @staticmethod
    def decompile_window_around_statement(addr, window_size=5):
        cfunc = idaapi.decompile(addr)
        if cfunc is None:
            return None

        item = cfunc.body.find_closest_addr(addr)
        y_holder = idaapi.int_pointer()
        if not cfunc.find_item_coords(item, None, y_holder):
            return None
        current_line = y_holder.value()

        lines = cfunc.get_pseudocode()
        start_line = max(0, current_line - window_size)
        end_line = min(len(lines), current_line + window_size + 1)

        context_lines = []
        for lnnum in range(start_line, end_line):
            line = idaapi.tag_remove(lines[lnnum].line)
            context_lines.append(line)

        return "\n".join(context_lines)

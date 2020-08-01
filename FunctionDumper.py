from __future__ import print_function
import idaapi
import idautils
import idc

action_name = "yamiM0NSTER:DumpFunction"

# class that both handles action activation and function dump functionality
class DumpFunction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        
    def dump_opcodes(self, start, end):
        opcodes = list()
        for ea in range(start, end):
            opcodes.append(idaapi.get_original_byte(ea))

        return opcodes
    
    def activate(self, ctx):
        # get cursor position
        screen_ea = ScreenEA()

        func = idaapi.get_func(screen_ea)
        if not func:
            idaapi.msg("No function at address [{:#x}]\n".format(screen_ea))
            return
        elif not func.does_return:
            idaapi.msg("Function at address [{:#x}] doesn't have an exit point...\n")
            return
        func_start = func.startEA
        func_end = func.endEA
        func_name = idc.GetFunctionName(func_start)
        idaapi.msg('---------------------------------------------------------------------------------------------\n');
        idaapi.msg("Function '{}' starts at [{:#x}] and ends at [{:#x}] Length: {}\n".format(func_name, func_start, func_end, func_end - func_start))

        # traverse code or data in function boundaries
        for head in idautils.Heads(func_start, func_end):
            # skip data?
            if not idc.isCode(idc.GetFlags(head)):
                continue
            next_head = idc.NextHead(head, func_end)
            #if last instruction, set end to func_end
            if next_head == BADADDR:
                next_head = func_end
            #idaapi.msg("Current inst: {:#x}, next inst: {:#x}".format(head, next_head))
            opcodes = self.dump_opcodes(head, next_head)
            printable_opcodes = ["{:02X}".format(op) for op in opcodes]
            idaapi.msg("{:#x}: [{}]\n".format(head, ' '.join(printable_opcodes)))

        idaapi.msg('---------------------------------------------------------------------------------------------\n');
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# class for dynamically attaching action to context menu
class Hooks(idaapi.UI_Hooks):
    def populating_tform_popup(self, form, popup):
        # You can attach here.
        pass
    def finish_populating_tform_popup(self, form, popup):
        if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
            #idaapi.msg("Registering action\n")
            idaapi.attach_action_to_popup(form, popup, action_name, None)

# class for plugin definition
class FunctionDumper_t(idaapi.plugin_t):
    # flags = idaapi.PLUGIN_UNL
    flags = 0
    comment = "Made by yamiM0NSTER"
    help = "-"
    wanted_name = "Function Dumper v1.0"
    wanted_hotkey = ""
    hooks = Hooks()
    def init(self):
        self.hooks.hook()
        act_desc = idaapi.action_desc_t(
            action_name,       # The action name. Must be unique
            "Dump Function",       # Action Text
            DumpFunction(), # Action handler
            None,           # Optional shortcut
            'Try to dump the function', # Action tooltip
            122             # Icon
        )
        idaapi.unregister_action(action_name)
        idaapi.register_action(act_desc)
        idaapi.msg("FunctionDumper initialized.\n")
        return idaapi.PLUGIN_KEEP
    def run(self, arg):
        #idaapi.msg("run() called with %d!\n" % arg)
        pass
    def term(self):
        idaapi.unregister_action(action_name)
        idaapi.msg("FunctionDumper termiinated.\n")

# Function called by IDA to start plugin
def PLUGIN_ENTRY():
    return FunctionDumper_t()
from symport.symbol_list import SymbolList

import ida_kernwin
import ida_name


class ImportSymbolsHandler(ida_kernwin.action_handler_t):
    def __init__(self) -> None:
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, context):
        if path := ida_kernwin.ask_file(False, "*.csv", "Import Symport CSV") is None:
            return

        symbol_list = SymbolList()
        symbol_list.load_csv(path)

        for address in symbol_list:
            ida_name.set_name(address, symbol_list[address])

        return 1

    def update(self, context):
        return ida_kernwin.AST_ENABLE_ALWAYS


import_symbols_action = ida_kernwin.action_desc_t(
    "symport:import_symbols", "Symport CSV file...", ImportSymbolsHandler()
)

ida_kernwin.register_action(import_symbols_action)
ida_kernwin.attach_action_to_menu(
    "File/Load file/Parse C header file...",
    "symport:import_symbols",
    ida_kernwin.SETMENU_APP,
)


class ExportSymbolsHandler(ida_kernwin.action_handler_t):
    def __init__(self) -> None:
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, context):
        ida_kernwin.warning("Exporting symbols is not yet supported.")
        return 1

    def update(self, context):
        return ida_kernwin.AST_ENABLE_ALWAYS


export_symbols_action = ida_kernwin.action_desc_t(
    "symport:export_symbols", "Symport CSV file...", ExportSymbolsHandler()
)

ida_kernwin.register_action(export_symbols_action)
ida_kernwin.attach_action_to_menu(
    "File/Produce file/Create C header file...",
    "symport:export_symbols",
    ida_kernwin.SETMENU_APP,
)

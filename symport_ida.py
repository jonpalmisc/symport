from symport.symbol_list import SymbolList

import ida_kernwin
import ida_name


def log(message: str) -> None:
    print(f"Symport: {message}")


class ImportSymbolsHandler(ida_kernwin.action_handler_t):
    def __init__(self) -> None:
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, context):
        if (path := ida_kernwin.ask_file(False, "*.csv", "Import Symport CSV")) is None:
            return

        log(f"Loading symbols from {path}")

        symbol_list = SymbolList()
        symbol_list.load_csv(path)

        for address in symbol_list:
            name = symbol_list[address]

            # Check for conflicting symbols
            current_name = ida_name.get_name(address)
            if current_name != "" and current_name != name:
                log(
                    f"Skipped symbol conflict at {hex(address)} (have '{current_name}', expected '{name}')"
                )
                continue

            # Check for duplicate symbols
            elif current_name == name:
                log(f"Skipped duplicate symbol '{name}' at {hex(address)}")
                continue

            # Define missing symbol
            else:
                log(f"Added symbol '{name}' at {hex(address)}")

            ida_name.set_name(address, name)

        return 1

    def update(self, context):
        return ida_kernwin.AST_ENABLE_ALWAYS


import_symbols_action = ida_kernwin.action_desc_t(
    "symport:import_symbols",
    "Symport CSV file...",
    ImportSymbolsHandler(),
    None,
    "Import symbols from a Symport CSV file",
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
    "symport:export_symbols",
    "Symport CSV file...",
    ExportSymbolsHandler(),
    None,
    "Export symbols to a Symport CSV file",
)

ida_kernwin.register_action(export_symbols_action)
ida_kernwin.attach_action_to_menu(
    "File/Produce file/Create C header file...",
    "symport:export_symbols",
    ida_kernwin.SETMENU_APP,
)

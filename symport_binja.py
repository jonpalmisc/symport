from symport.symbol_list import SymbolList

from binaryninja import (
    BinaryView,
    Logger,
    PluginCommand,
    Symbol,
    SymbolType,
    get_open_filename_input as get_open_path,
    get_save_filename_input as get_save_path,
)

logger = Logger(0, "Symport")


def export_symbols(bv: BinaryView):
    if (path := get_save_path("Export Symport CSV", "*.csv", "symbols.csv")) is None:
        return

    symbol_list = SymbolList()

    for name in bv.symbols:
        symbol = bv.symbols[name][0]
        symbol_list.insert(symbol.address, name)

    symbol_list.save_csv(path)


def import_symbols(bv: BinaryView):
    if (path := get_open_path("Import Symport CSV", "*.csv")) is None:
        return

    logger.log_info(f"Loading symbols from {path}")

    symbol_list = SymbolList()
    symbol_list.load_csv(path)

    for address in symbol_list:
        name = symbol_list[address]

        if (func := bv.get_function_at(address)) is None:
            symbol_type = SymbolType.DataSymbol
        else:
            symbol_type = SymbolType.FunctionSymbol

        current_symbol = bv.get_symbol_at(address)
        if current_symbol != None:
            current_name = current_symbol.short_name
        else:
            current_name = None

        # Check for conflicting symbols
        if current_name != None and current_name != name:
            logger.log_warn(
                f"Skipped symbol conflict at {hex(address)} (have '{current_name}', expected '{name}')"
            )
            continue

        # Check for duplicate symbols
        elif current_name == name:
            logger.log_info(f"Skipped duplicate symbol '{name}' at {hex(address)}")
            continue

        # Define missing symbol
        else:
            logger.log_info(f"Added symbol '{name}' at {hex(address)}")

        symbol = Symbol(symbol_type, address, symbol_list[address])
        bv.define_user_symbol(symbol)


PluginCommand.register("Symport\\Import Symbols from File", "", import_symbols)
PluginCommand.register("Symport\\Export Symbols to File", "", export_symbols)

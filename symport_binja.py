from symport.symbol_list import SymbolList

from binaryninja import (
    BinaryView,
    PluginCommand,
    Symbol,
    SymbolType,
    get_open_filename_input as get_open_path,
    get_save_filename_input as get_save_path,
)


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

    symbol_list = SymbolList()
    symbol_list.load_csv(path)

    for address in symbol_list:
        func = bv.get_function_at(address)
        if func is None:
            symbol_type = SymbolType.DataSymbol
        else:
            symbol_type = SymbolType.FunctionSymbol

        symbol = Symbol(symbol_type, address, symbol_list[address])
        bv.define_user_symbol(symbol)


PluginCommand.register("Symport\\Import Symbols from File", "", import_symbols)
PluginCommand.register("Symport\\Export Symbols to File", "", export_symbols)

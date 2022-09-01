product = None

try:
    import idaapi

    product = "ida"
except ImportError:
    pass
try:
    import binaryninja

    product = "binja"
except ImportError:
    pass

if product == "ida":
    import symport.plugin_ida
elif product == "binja":
    import symport.plugin_binja
else:
    raise NotImplementedError("Unknown or unsupported disassembler")

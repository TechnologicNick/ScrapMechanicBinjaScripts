from binaryninja import *
from typing import cast

bv = cast(BinaryView, bv) # type: ignore

def extractAddress(ref: ReferenceSource) -> int:
    for var in ref.hlil.parent.parent.medium_level_il.vars_read:
        for token in var.def_site.traverse(lambda x: x):
            if isinstance(token, MediumLevelILConstPtr):
                return token.constant
            
    for token in ref.hlil.parent.parent.medium_level_il.traverse(lambda x: x):
        if isinstance(token, MediumLevelILConstPtr):
            return token.constant

for string in [s for s in bv.strings if re.match(r"g_\w+ == nullptr", s.value)]:
    print(hex(string.start), string)

    var = DataVariable(bv, string.start, Type.pointer(bv.arch, Type.char()), True)
    for ref in var.code_refs:
        if not ref.hlil:
            continue
        print(ref.hlil.parent.parent)

        address = extractAddress(ref)
        print(hex(address) if address else None)

        if not address:
            raise ValueError(f"Could not extract address for {string}")
        
        global_name = string.value.split(" ")[0]

        symbol = bv.get_symbol_at(address)
        if not symbol:
            bv.define_user_symbol(Symbol(SymbolType.DataSymbol, address, global_name))

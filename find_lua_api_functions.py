from binaryninja import *
from typing import cast

bv = cast(BinaryView, bv) # type: ignore

[luaL_register] = bv.get_symbols_by_name(
    "luaL_register", ordered_filter=[SymbolType.ImportAddressSymbol]
)
print(luaL_register)

register_var = DataVariable(
    bv,
    luaL_register.address,
    Type.pointer(
        bv.arch,
        Type.function(
            Type.void(),
            [
                Type.pointer(bv.arch, Type.void()),
                Type.pointer(bv.arch, Type.char()),
                Type.pointer(bv.arch, Type.void()),
            ],
        ),
    ),
    True,
)

if not bv.get_tag_type("Lua API"):
    bv.create_tag_type("Lua API", "🌌")

# typedef struct luaL_Reg {
#   const char *name;
#   lua_CFunction func;
# } luaL_Reg;

def assert_string_reference_at(address: int) -> StringReference:
    """Get the string reference at the given address, or create a new one if it doesn't exist."""

    funcname = bv.get_string_at(address)
    if not funcname:
        funcname = bv.get_ascii_string_at(address, min_length=0)
        bv.define_user_data_var(address, Type.array(Type.char(), funcname.length))

    return funcname

for ref in register_var.code_refs:
    print(ref.mlil)
    [_, libname, reg_ptr] = [x[1] for x in ref.mlil.detailed_operands if x[0] == "params"][0]

    if not isinstance(libname, MediumLevelILConstPtr):
        continue

    libname = assert_string_reference_at(cast(MediumLevelILConstPtr, libname).constant)
    reg_ptr = cast(MediumLevelILConstPtr, reg_ptr).constant

    i = 0
    while True:
        reg = bv.read_pointer(reg_ptr + i * 0x10)
        if not reg:
            break

        funcname = assert_string_reference_at(reg)

        func = bv.get_function_at(bv.read_pointer(reg_ptr + i * 0x10 + 8))

        print(funcname, func)

        func.name = f"LuaAPI::{libname}.{funcname}"
        
        if not any(func.get_function_tags(auto=None, tag_type="Lua API")):
            func.add_tag(tag_type="Lua API", data=f"{libname}.{funcname}", auto=False)

        i += 1


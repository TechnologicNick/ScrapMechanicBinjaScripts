from binaryninja import *
from typing import cast

bv = cast(BinaryView, bv) # type: ignore

sm_types = bv.parse_types_from_string("""
                                      
struct LuaClassDefinition __packed
{
    char const* m_pClassName;
    uint32_t m_uTypeId;
    uint32_t m_uDomain;
    void* m_pCallbackToString;
    void* m_pCallbackSomeBoolean;
    void* m_pCallbackSerialize;
    void* m_pCallbackDeserialize;
};
                                      
""")

for name in sm_types.types:
    bv.define_user_type(name, sm_types.types[name])

LuaClassDefinition = cast(StructureType, bv.get_type_by_name("LuaClassDefinition"))

def get_member(struct: StructureType, member_name: str) -> StructureMember:
    return next(cast(StructureMember, mem) for mem in struct.members if mem.name == member_name)

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

def rename_lua_functions(libname, reg_ptr):
    i = 0
    while True:
        reg = bv.read_pointer(reg_ptr + i * 0x10)
        if not reg:
            break

        funcname = assert_string_reference_at(reg)

        func = bv.get_function_at(bv.read_pointer(reg_ptr + i * 0x10 + 8))

        print("   ", hex(func.start), funcname, func)

        func.name = f"LuaAPI::{libname}{funcname}"
            
        if not any(func.get_function_tags(auto=None, tag_type="Lua API")):
            func.add_tag(tag_type="Lua API", data=f"{libname}{funcname}", auto=False)

        i += 1

def find_static_functions() -> None:
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

    for ref in register_var.code_refs:
        print(ref.mlil)
        [_, libname, reg_ptr] = [x[1] for x in ref.mlil.detailed_operands if x[0] == "params"][0]

        if not isinstance(libname, MediumLevelILConstPtr):
            continue

        libname = assert_string_reference_at(cast(MediumLevelILConstPtr, libname).constant)
        reg_ptr = cast(MediumLevelILConstPtr, reg_ptr).constant

        rename_lua_functions(libname.value + ".", reg_ptr)

def register_class(name: str, typeid: int, metatable_ptr: int, member_functions_ptr: int) -> None:
    print(name, typeid, hex(metatable_ptr), hex(member_functions_ptr))

    if metatable_ptr:
        rename_lua_functions(name + ":", metatable_ptr)
    if member_functions_ptr:
        rename_lua_functions(name + ":", member_functions_ptr)

def read_const_char_ptr_argument(hlil: HighLevelILInstruction, index: int) -> Optional[Tuple[StringReference, Optional[int]]]:
    if not isinstance(hlil, HighLevelILCall):
        raise Exception(f"Reference at {hex(hlil.address)} is not a call")
    
    param = hlil.params[1]
    if isinstance(param, HighLevelILDeref) or isinstance(param, HighLevelILDerefField):
        if isinstance(param.src, HighLevelILConstPtr):
            return (assert_string_reference_at(bv.read_pointer(param.src.constant)), param.src.constant)
        elif isinstance(param.src, HighLevelILVar):
            # TODO: Support the class registration function that takes the name from an argument
            print(f"Skipping class registration function at {hex(hlil.address)}")
            return None
        else:
            raise Exception(f"Reference at {hex(hlil.address)} is not a deref: {param.src} ({type(param.src)})")
    elif isinstance(param, HighLevelILConstPtr):
        return (assert_string_reference_at(param.constant), None)
    else:
        raise Exception(f"Reference at {hex(hlil.address)} is not a char pointer: {param} ({type(param)})")

def assert_hlil_calls_function(hlil_function: HighLevelILInstruction, func: CoreSymbol) -> HighLevelILCall:
    if not isinstance(hlil_function, HighLevelILCall):
        raise Exception(f"Reference at {hex(hlil_function.address)} is not a call")
        
    operand = hlil_function.operands[0]
    if not isinstance(operand, HighLevelILImport):
        raise Exception(f"Reference at {hex(hlil_function.address)} is not an import")

    if operand.constant != func.address:
        raise Exception(f"Reference at {hex(hlil_function.address)} is not a call to {func.name}")
    
    return hlil_function

def update_function_name(func: Function, new_function_name: str) -> str:
    combined = "::".join(func.name.split("::")[0:-1] + [new_function_name])
    func.name = combined
    return combined

def find_classes() -> None:
    [luaL_newmetatable] = bv.get_symbols_by_name(
        "luaL_newmetatable", ordered_filter=[SymbolType.ImportAddressSymbol]
    )
    [lua_pushinteger] = bv.get_symbols_by_name(
        "lua_pushinteger", ordered_filter=[SymbolType.ImportAddressSymbol]
    )
    [luaL_register] = bv.get_symbols_by_name(
        "luaL_register", ordered_filter=[SymbolType.ImportAddressSymbol]
    )

    newmetatable_var = DataVariable(
        bv,
        luaL_newmetatable.address,
        Type.pointer(
            bv.arch,
            Type.function(
                Type.int(32),
                [
                    Type.pointer(bv.arch, Type.char()),
                ],
            ),
        ),
        True,
    )

    class_registration_refs: set[ReferenceSource] = set()

    for ref in newmetatable_var.code_refs:
        hlil_newmetatable = ref.hlil
        if not hlil_newmetatable:
            raise Exception(f"Reference at {hex(ref.address)} is not HLIL")
        
        name = read_const_char_ptr_argument(hlil_newmetatable, 1)
        if not name:
            class_registration_refs.add(ref)
            continue

        (name, name_ptr) = name

        # Rename the function to include the class name
        if name.value == "weak":
            new_function_name = "CreateLuaVm"
        else:
            new_function_name = f"RegisterClass_{name.value}"
        func = ref.function
        new_function_name = update_function_name(func, new_function_name)
        print(hex(func.start), new_function_name)

        # Not a class registration function
        if name.value == "weak":
            continue

        # Rename the data variable to the class name
        data_var = bv.get_data_var_at(name.start)
        data_var.name = f"s_LuaAPI::Class::{name.value}"

        # Rename the pointer to the class name
        if name_ptr:
            data_var = bv.get_data_var_at(name_ptr)
            data_var.name = f"ps_LuaAPI::Class::{name.value}"


        instructions = list(func.hlil.instructions)
        
        hlil_pushinteger = assert_hlil_calls_function(instructions[hlil_newmetatable.instr_index + 1], lua_pushinteger)

        param_typeid = hlil_pushinteger.params[1]
        assert isinstance(param_typeid, HighLevelILSx), f"Reference at {hex(hlil_pushinteger.address)} is not a sign extend"
        assert isinstance(param_typeid.src, HighLevelILDeref), f"Reference at {hex(hlil_pushinteger.address)} is not a deref"
        assert isinstance(param_typeid.src.src, HighLevelILConstPtr), f"Reference at {hex(hlil_pushinteger.address)} is not a const ptr"
        typeid = bv.get_data_var_at(param_typeid.src.src.constant)
        typeid.name = f"LuaAPI::Class::{name.value}::TypeId_{typeid.value}"

        hlil_register_metatable = assert_hlil_calls_function(instructions[hlil_pushinteger.instr_index + 2], luaL_register)

        assert isinstance(hlil_register_metatable.params[1], HighLevelILConst), f"Reference at {hex(hlil_register_metatable.address)} is not a const"
        assert hlil_register_metatable.params[1].constant == 0, f"Reference at {hex(hlil_register_metatable.address)} is not a null pointer"

        assert isinstance(hlil_register_metatable.params[2], HighLevelILConstPtr), f"Reference at {hex(hlil_register_metatable.address)} is not a const ptr"
        metatable_ptr = hlil_register_metatable.params[2].constant
        metatable_ptr_var = bv.get_data_var_at(metatable_ptr)
        metatable_ptr_var.name = f"p_LuaAPI::Class::{name.value}::Metatable"

        hlil_register_member_functions = assert_hlil_calls_function(instructions[hlil_register_metatable.instr_index + 1], luaL_register)

        assert isinstance(hlil_register_member_functions.params[1], HighLevelILConst), f"Reference at {hex(hlil_register_member_functions.address)} is not a const"
        assert hlil_register_member_functions.params[1].constant == 0, f"Reference at {hex(hlil_register_member_functions.address)} is not a null pointer"

        assert isinstance(hlil_register_member_functions.params[2], HighLevelILConstPtr), f"Reference at {hex(hlil_register_member_functions.address)} is not a const ptr"
        member_functions_ptr = hlil_register_member_functions.params[2].constant
        member_functions_ptr_var = bv.get_data_var_at(member_functions_ptr)
        member_functions_ptr_var.name = f"p_LuaAPI::Class::{name.value}::MemberFunctions"


        register_class(name.value, typeid.value, metatable_ptr, member_functions_ptr)

    assert len(class_registration_refs) == 1, f"Expected 1 class registration function references, got {len(class_registration_refs)}"
    for ref in class_registration_refs:
        print("Found class registration function at", ref)
        func = ref.function
        assert func, "Reference has no function"

        update_function_name(ref.function, "RegisterClass")

        func.parameter_vars[0].name = "L"
        func.parameter_vars[1].type = Type.pointer(bv.arch, LuaClassDefinition)
        func.parameter_vars[1].name = "pDefinition"
        func.parameter_vars[2].name = "pMetatable"
        func.parameter_vars[3].name = "pMemberFunctions"

        for ref in DataVariable(bv, func.start, Type.pointer(bv.arch, Type.void()), True).code_refs:
            print(ref.hlil)
            assert isinstance(ref.hlil, HighLevelILCall), f"Reference at {hex(ref.address)} is not a call"
            
            assert isinstance(ref.hlil.params[1], HighLevelILConstPtr), f"Reference at {hex(ref.address)} is not a const ptr: {ref.hlil.params[1]} ({type(ref.hlil.params[1])})"
            lua_class_definition_addr = ref.hlil.params[1].constant
            lua_class_definition = bv.get_data_var_at(lua_class_definition_addr)
            lua_class_definition.type = LuaClassDefinition

            class_name_addr = bv.read_pointer(lua_class_definition_addr)
            class_name = assert_string_reference_at(class_name_addr)
            print(LuaClassDefinition, class_name)
            bv.get_data_var_at(class_name_addr).name = f"s_LuaAPI::Class::{class_name.value}"
            lua_class_definition.name = f"LuaAPI::Class::{class_name}::Definition"

            member = get_member(LuaClassDefinition, "m_uTypeId")
            typeid = bv.read_int(lua_class_definition_addr + member.offset, member.type.width)

            if isinstance(ref.hlil.params[2], HighLevelILConst):
                assert ref.hlil.params[2].constant == 0, f"Reference at {hex(ref.address)} is not a null pointer: {ref.hlil.params[2].constant}"
                metatable_ptr = 0
            else:
                assert isinstance(ref.hlil.params[2], HighLevelILConstPtr), f"Reference at {hex(ref.address)} is not a const ptr: {ref.hlil.params[2]} ({type(ref.hlil.params[2])})"
                metatable_ptr = ref.hlil.params[2].constant
                metatable_var = bv.get_data_var_at(metatable_ptr)
                metatable_var.name = f"p_LuaAPI::Class::{class_name}::Metatable"

            if isinstance(ref.hlil.params[3], HighLevelILConst):
                assert ref.hlil.params[3].constant == 0, f"Reference at {hex(ref.address)} is not a null pointer: {ref.hlil.params[3].constant}"
                member_functions_ptr = 0
            else:
                assert isinstance(ref.hlil.params[3], HighLevelILConstPtr), f"Reference at {hex(ref.address)} is not a const ptr: {ref.hlil.params[3]} ({type(ref.hlil.params[3])})"
                member_functions_ptr = ref.hlil.params[3].constant
                member_functions_var = bv.get_data_var_at(member_functions_ptr)
                member_functions_var.name = f"p_LuaAPI::Class::{class_name}::MemberFunctions"

            register_class(class_name.value, typeid, metatable_ptr, member_functions_ptr)
            

# find_static_functions()
find_classes()
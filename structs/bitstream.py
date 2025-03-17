from binaryninja import *
from typing import cast
from itertools import chain

bv = cast(BinaryView, bv) # type: ignore

def find_string_references(string: str):
    matches = [s for s in bv.strings if s.length == len(string) and s.value == string]
    data_refs = [bv.get_code_refs(s.start) for s in matches]
    return chain(*data_refs)

def find_function_with_strings(strings: list[str]):
    intersection = None
    for string in strings:
        refs = find_string_references(string)
        functions = set([ref.function for ref in refs if ref.function])
        print(f"Found {len(functions)} functions with string {string}", functions)

        if intersection is None:
            intersection = functions
        else:
            intersection &= functions
    return intersection or set()

def update_function_signature(func: Function, signature: str):
    (parsed_type, parsed_qualname) = bv.parse_type_string(signature)
    func.type = parsed_type
    func.name = str(parsed_qualname)
    return func

def define_bitstream():
    (struct, name) = bv.parse_type_string("""
    struct BitStream __packed {
        uint32_t bitReadOffset;
        uint32_t currentBitPosition;
        char m_inlineBuffer[256];
        void* srcByteBuffer;
        uint32_t bitCapacity;
        bool m_bOwnsData;
        __padding char field6_0x115;
        __padding char field7_0x116;
        __padding char field8_0x117;
    };
    """)

    bv.define_user_type(name, Type.structure_type(struct))

    print("Searching for Player::SerializeGenericData_PlayerSaveFileData")
    for func in find_function_with_strings([r"Z:\Build\sm_legacy\ContraptionCommon\PlayerManager.cpp", r"eResult == BlobDataManager::Result::Success"]):
        block = next(func.llil_basic_blocks)
        calls = [instr for instr in block if isinstance(instr, LowLevelILCall)]
        print(f"Found {len(calls)} calls in {func.name}", calls)
        if len(calls) != 11:
            continue

        targets = [bv.get_function_at(call.dest.value.value) for call in calls]

        if targets[0].name != "memset":
            continue

        func.name = "Player::SerializeGenericData_PlayerSaveFileData"

        update_function_signature(targets[1], "void `BitStream::Write2`(BitStream* bitstream, uint16_t* data);")
        update_function_signature(targets[2], "void `BitStream::WriteVec3f`(BitStream* bitstream, Vec3f* data);")
        assert targets[2] == targets[3]
        update_function_signature(targets[4], "void `BitStream::Write4`(BitStream* bitstream, uint32_t* data);")
        assert len(set([targets[4], targets[5], targets[7], targets[8], targets[9]])) == 1
        update_function_signature(targets[6], "void `BitStream::Write8`(BitStream* bitstream, uint64_t* data);")

        break
    else:
        raise ValueError("Could not find Player::SerializeGenericData_PlayerSaveFileData")
        
define_bitstream()
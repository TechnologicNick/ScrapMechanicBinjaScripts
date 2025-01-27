from binaryninja import *
from typing import cast

bv = cast(BinaryView, bv) # type: ignore

function_to_struct_members: dict[Function, list[tuple[StructureType, InheritedStructureMember]]] = {}

for vtable in bv.types.values():
    if not isinstance(vtable, StructureType):
        continue

    name = vtable.tokens[-1].text

    if not name.endswith("::VTable"):
        continue
    
    print(vtable, vtable.width)

    count = 0
    
    # Find where the vtable is defined
    refs = list(bv.get_data_refs_for_type(name))
    for ref in refs:
        rtti_complete_object_locator = bv.read_pointer(ref - bv.arch.address_size)
        rtti_type_descriptor_offset = bv.read_int(rtti_complete_object_locator + 12, size=4)
        rtti_type_descriptor = bv.image_base + rtti_type_descriptor_offset
        rtti_type_descriptor_name_mangled = bv.get_string_at(rtti_type_descriptor + 16)
        rtti_type_descriptor_name = demangle_ms(bv.arch, str(rtti_type_descriptor_name_mangled), options=bv)
        (named_type_reference_type, segments) = rtti_type_descriptor_name
        full_name = "::".join(segments) + "::VTable" if type(segments) == list else segments

        # if type(segments) == list:
        #     continue

        if (name.endswith(full_name) or len(refs) == 1):
            print("   ", hex(ref), full_name)
            count += 1
            struct_definition = ref
        else:
            print("    ~~", hex(ref), full_name)
        
    if count > 1:
        raise Exception(f"Expected at most 1 definition for {name}, found {count}")
    elif count == 0:
        print("    No definition found for", name)
        continue
    

    for i in range(vtable.width // bv.arch.address_size):
        offset = i * bv.arch.address_size
        member_function_address = bv.read_pointer(struct_definition + offset)

        if member_function_address == 0:
            continue

        member = vtable.member_at_offset_including_inherited(bv, offset)
        if not member:
            raise Exception(f"Member not found at offset {offset} in {vtable}")
        
        func = bv.get_function_at(member_function_address)

        # data_refs = list(bv.get_data_refs(member_function_address))
        
        print("       ", hex(member_function_address), member)

        if not func:
            raise Exception(f"Function not found at {hex(member_function_address)}")

        if function_to_struct_members.get(func):
            function_to_struct_members[func].append((vtable, member))
        else:
            function_to_struct_members[func] = [(vtable, member)]


if not bv.get_tag_type("VTable Function"):
    bv.create_tag_type("VTable Function", "📋")

for (func, struct_members) in function_to_struct_members.items():
    print(hex(func.start))
    for (vtable, member) in struct_members:
        print("   ", vtable, member)

    # If the function is only in one vtable, we can name it after the vtable
    if len(struct_members) == 1:
        (vtable, member) = struct_members[0]

        segments = vtable.tokens[-1].text.split("::")
        segments.pop(-1) # Remove "VTable"
        segments.append(f"vFunc_{member.member_index}")

    # If the function is used multiple times, but in the same vtable, we can name it after the vtable
    elif len(struct_members) > 1 and len(set([vtable for (vtable, member) in struct_members])) == 1:
        (vtable, _) = struct_members[0]

        segments = vtable.tokens[-1].text.split("::")
        segments.pop(-1) # Remove "VTable"
        segments.append("vFunc_" + "_".join([str(member.member_index) for (vtable, member) in struct_members]))

    # If the function is used in multiple vtables, that all inherit from the same base class,
    # and the function is at the same offset in all of them, we can name it after the base class
    elif len(struct_members) > 1 \
        and (struct_members[0][1].base != None) \
        and len(
            set([(member.base.name if member.base != None else None, member.member_index) for (vtable, member) in struct_members])
        ) == 1:
        (vtable, member) = struct_members[0]

        segments = member.base.tokens[-1].text.split("::")
        segments.pop(-1) # Remove "VTable"
        segments.append(f"vFunc_{member.member_index}")

    # If the function is used in multiple vtables, and most of them inherit from the same base class,
    # but the function is also used in a vtable that doesn't inherit from the base class, we assume that the
    # function is a virtual function of the base class, and name it after the base class
    elif len(struct_members) > 1 \
        and any([member.base == None for (vtable, member) in struct_members]) \
        and any([member.base != None for (vtable, member) in struct_members]) \
        and len(
            set([(member.base.name if member.base != None else None, member.member_index) for (vtable, member) in struct_members])
        ) == 2:
        (vtable, member) = [x for x in struct_members if x[1].base != None][0]

        segments = member.base.tokens[-1].text.split("::")
        segments.pop(-1) # Remove "VTable"
        segments.append(f"vFunc_{member.member_index}")

    # If the function is used in multiple vtables, we find the namespace that contains all the vtables
    # and name the function after that
    elif len(struct_members) > 1 and len(set([vtable.tokens[-1].text.split("::")[0] for (vtable, member) in struct_members])) == 1:
        # Find the common start and end of the names
        # Example:
        #   CCallbackBase::CCallResult<class SteamWorkshopManager, struct CreateItemResult_t>::VTable
        #   CCallbackBase::CCallResult<class SteamWorkshopManager, struct SteamUGCQueryCompleted_t>::VTable
        #   CCallbackBase::CCallResult<class SteamWorkshopManager, struct SubmitItemUpdateResult_t>::VTable
        # to
        #   CCallbackBase::CCallResult<class SteamWorkshopManager, struct *_t>::VTable

        names = [vtable.tokens[-1].text for (vtable, member) in struct_members]

        # Find longest common suffix first
        min_length = min(len(name) for name in names)
        common_suffix_len = 0
        while common_suffix_len < min_length and all(name[-common_suffix_len-1] == names[0][-common_suffix_len-1] for name in names):
            common_suffix_len += 1

        # Then find longest common prefix, but don't overlap with suffix
        max_prefix_len = min_length - common_suffix_len
        common_prefix_len = 0
        while common_prefix_len < max_prefix_len and all(name[common_prefix_len] == names[0][common_prefix_len] for name in names):
            common_prefix_len += 1

        distinct_parts = sorted(set(name[common_prefix_len:-common_suffix_len] for name in names))

        if len(distinct_parts) > 5:
            distinct_parts = distinct_parts[:5] + ["..."]
        if len("|".join(distinct_parts)) > 50:
            distinct_parts = ["|".join(distinct_parts)[:50] + "..."]

        distinct_parts_str = "(" + "|".join(distinct_parts) + ")" if len(distinct_parts) > 0 else ""
        common_name = names[0][:common_prefix_len] + distinct_parts_str + names[0][-common_suffix_len:] if common_suffix_len > 0 else names[0][:common_prefix_len] + distinct_parts_str

        segments = [common_name.removesuffix("::VTable")]

    else:
        continue

    func.add_tag(tag_type="VTable Function", data="::".join(segments), auto=False)
    segments.append(func.name.removeprefix("::".join(segments)).removeprefix("::"))
    function_name = "::".join(segments)
    print("   ", "Assigning name", function_name)
    func.name = function_name

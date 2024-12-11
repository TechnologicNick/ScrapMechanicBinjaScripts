from binaryninja import *
from typing import cast

bv = cast(BinaryView, bv) # type: ignore

path_prefix = "Z:\\Build\\"

name_to_function: dict[str, Function] = {}

files_per_function: dict[str, dict[str, int]] = {}
functions_per_file = {}

for string in [s for s in bv.strings if path_prefix in s.value]:
    # print(string)
    var = DataVariable(bv, string.start, Type.pointer(bv.arch, Type.char()), True)
    for ref in var.code_refs:
        if ref.function.name not in files_per_function:
            files_per_function[ref.function.name] = {}
            name_to_function[ref.function.name] = ref.function
        files_per_function[ref.function.name][string.value] = files_per_function[ref.function.name].get(string.value, 0) + 1

        functions_per_file[string.value] = functions_per_file.get(string.value, 0) + 1

# for function_name in files_per_function:
#     print(function_name)
#     for file_name in files_per_function[function_name]:
#         print(f"  {file_name}: {files_per_function[function_name][file_name]}")

functions_per_file = {k: v for k, v in sorted(functions_per_file.items(), key=lambda item: item[1], reverse=True)}

# for file_name in functions_per_file:
#     print(f"{file_name}: {functions_per_file[file_name]}")

if not bv.get_tag_type("File Name"):
    bv.create_tag_type("File Name", "📂")

for function_name in files_per_function:
    func = name_to_function[function_name]
    files = files_per_function[function_name]

    # If a function has multiple files, we'll just use the one that appears the least in the binary (functions_per_file)
    file_name = min(files, key=lambda x: functions_per_file[x])

    basename = file_name.split("\\")[-1]
    if not func.name.startswith(f"{basename}::"):
        func.name = f"{basename}::{function_name}"
    
    if not any(func.get_function_tags(auto=None, tag_type="File Name")):
        func.add_tag(tag_type="File Name", data=file_name, auto=False)
    

from os.path import dirname

files = [
    "prepend_source_file_name.py",
    "find_lua_api_functions.py",
    "find_globals.py",
    "prepend_vftable_names.py",
    "structs/common.py",
    "structs/bitstream.py",
]

for file in files:
    with open(dirname(__file__) + f"/{file}", "r") as f:
        exec(f.read())
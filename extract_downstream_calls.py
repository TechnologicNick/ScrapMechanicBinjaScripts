from binaryninja import *
from typing import cast
import json
import os.path as path

bv = cast(BinaryView, bv) # type: ignore

@dataclass
class CallToTarget:
    source: int
    target: int
    method: str
    external_library: Optional[str]
    target_name: str

    def __repr__(self):
        return f"CallToTarget({hex(self.source)}, {hex(self.target)}, {self.method}, {self.external_library}, {self.target_name})"

    def __hash__(self):
        return hash((self.source, self.target, self.method, self.external_library, self.target_name))
    
    def to_json(self):
        return {
            "source": hex(self.source),
            "target": hex(self.target),
            "method": self.method,
            "external_library": self.external_library,
            "target_name": self.target_name,
        }
    
    @staticmethod
    def from_json(data):
        return CallToTarget(int(data["source"], 16), int(data["target"], 16), data["method"], data["external_library"], data["target_name"])

function_to_calls: dict[int, set[CallToTarget]] = {}

external_address_to_location: dict[int, ExternalLocation] = {}
for location in bv.get_external_locations():
    external_address_to_location[location.source_symbol.address] = location

total = len(bv.functions)
for (i, func) in enumerate(bv.functions):
    if i % 1000 == 0:
        print(f"{i}/{total}", hex(func.start), func.name)

    # if i <= 44000:
    #     continue

    name = func.name.split("::")[-1]

    if not name.startswith("sub_"):
        continue

    namespace = func.name.split("::")[:-1]

    # print(hex(func.start), func.name)

    if func.analysis_skipped:
        func.analysis_skipped = False
        func.mark_updates_required(FunctionUpdateType.FullAutoFunctionUpdate)
        bv.update_analysis_and_wait()

    for llil in func.llil:
        for instr in llil:
            if instr.operation == LowLevelILOperation.LLIL_CALL:
                # print(f"  {hex(instr.address)} {instr}", instr.operands, type(instr.operands[0]))
                target = instr.operands[0]
                if isinstance(target, LowLevelILConstPtr):
                    constant = target.constant
                    method = "constant"
                elif isinstance(target, LowLevelILLoad):
                    # print(f"    {hex(instr.address)} {instr}", instr.operands, type(instr.operands[0]))
                    if target.src.value.value == 0:
                        # print(f"    {hex(target.src.value.value)} -> pure virtual")
                        constant = target.src.value.value
                        method = "pure_virtual"
                    else:
                        try:
                            constant = bv.read_pointer(target.src.value.value)
                            method = "load"
                        except Exception as e:
                            # print(f"        {hex(instr.address)} {target.src.value.value}")
                            # raise e
                            constant = target.src.value.value
                            method = "load_not_pointer"
                        
                        # print(f"    {hex(target.src.value.value)} -> {hex(constant)}")
                elif isinstance(target, LowLevelILReg):
                    method = "register"
                    constant = 0
                else:
                    raise ValueError(f"Instruction {instr} {hex(instr.address)} of function at {hex(func.start)} uses unknown operand type {type(target)}")

                calls = function_to_calls.get(func.start, set())

                if target_func := bv.get_function_at(constant):
                    calls.add(CallToTarget(
                        source=instr.address,
                        target=target_func.start,
                        method=method,
                        external_library=None,
                        target_name=target_func.name,
                    ))
                elif external_location := external_address_to_location.get(constant):
                    calls.add(CallToTarget(
                        source=instr.address,
                        target=constant,
                        method=method,
                        external_library=external_location.library.name,
                        target_name=external_location.source_symbol.full_name,
                    ))
                elif method == "register":
                    assert isinstance(instr, LowLevelILCall)
                    calls.add(CallToTarget(
                        source=instr.address,
                        target=constant,
                        method=method,
                        external_library=None,
                        target_name="".join([token.text for token in instr.dest.tokens]),
                    ))
                elif method == "pure_virtual" or constant == 0:
                    calls.add(CallToTarget(
                        source=instr.address,
                        target=constant,
                        method=method,
                        external_library=None,
                        target_name="pure virtual",
                    ))
                elif method == "load_not_pointer":
                    calls.add(CallToTarget(
                        source=instr.address,
                        target=constant,
                        method=method,
                        external_library=None,
                        target_name="not pointer",
                    ))
                else:
                    raise ValueError(f"Function at {hex(func.start)} calls a non-existent function {hex(constant)} {method}")
                
                function_to_calls[func.start] = calls

with open(path.join(path.dirname(__file__), "function_to_calls.json"), "w") as f:
    json.dump({
        "name": bv.file.filename,
        "function_to_calls": {
            hex(k): [x.to_json() for x in v] for k, v in function_to_calls.items()
        }
    }, f, indent='\t')

print("Done")
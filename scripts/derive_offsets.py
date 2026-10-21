# derive aarch64 forge offsets from the live ASan binary's DWARF
import json, subprocess, sys

B = "/home/user/php-firing-range/research/src/php-src-83/sapi/cli/php"
gdb_cmds = """
set pagination off
printf "FCI_size %d\\n", sizeof(zend_fcall_info)
printf "FCI_function_name %d\\n", &((zend_fcall_info*)0)->function_name
printf "FCI_function_val %d\\n", &((zend_fcall_info*)0)->function_name.value
printf "FCI_function_type %d\\n", (int)&((zend_fcall_info*)0)->function_name.u1.type_info - (int)&((zend_fcall_info*)0)->function_name
printf "IF_size %d\\n", sizeof(zend_internal_function)
printf "IF_handler %d\\n", &((zend_internal_function*)0)->handler
printf "IF_type %d\\n", &((zend_internal_function*)0)->type
printf "ZVAL_sizeof %d\\n", sizeof(zval)
printf "HT_sizeof %d\\n", sizeof(HashTable)
quit
"""
r = subprocess.run(["gdb", "-batch", "-ex", gdb_cmds, B],
                   capture_output=True, text=True, timeout=180)
vals = {}
for line in r.stdout.splitlines():
    if " " in line and line.rsplit(" ", 1)[-1].lstrip("-").isdigit():
        k, v = line.rsplit(" ", 1)
        vals[k.split()[-1]] = int(v)
print(json.dumps(vals, indent=1))
missing = {"FCI_size","FCI_function_val","IF_handler","IF_type","ZVAL_sizeof","HT_sizeof"} - vals.keys()
print("MISSING:", missing or "none", file=sys.stderr)
if not missing:
    out = {
        "arch": "aarch64",
        "fci_size": vals["FCI_size"],
        # their forge writes fn ptr into function_name.value (zval val slot)
        "off_fn": vals["FCI_function_val"],
        "off_type": vals["FCI_function_type"] + vals["FCI_function_name"],
        "off_cmd": None,  # command string placement stays empirical
        "off_internal_flag": vals["IF_type"],
        "off_handler": vals["IF_handler"],
    }
    json.dump(out, open("/tmp/asan-lab/aarch64-offsets.json", "w"), indent=1)
    print(json.dumps(out, indent=1))

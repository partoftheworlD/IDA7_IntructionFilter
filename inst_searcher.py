import idc                               
import idaapi
import re     

reg_value = re.compile(r'.*ebp\+arg_0*')

stack_view = []

def range_reverse(start, stop):
    for i in FuncItems(stop):
        if i < start and i >= stop:
            yield i

print "\n\n     Addr |              Instruction |"
print "-"*46
for j in stack_view:         
    current_function = idaapi.get_func(j)
    print "-"*46
    for i in range_reverse(current_function.endEA, current_function.startEA):
        disasm_output = idc.GetDisasm(i)
        if reg_value.findall(disasm_output):
            print("0x{} -- {}".format(hex(i)[2:].replace("L", "").upper(), disasm_output)) 

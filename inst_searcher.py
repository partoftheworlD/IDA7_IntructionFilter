import idc                               
import idaapi
import re      


reg_value = re.compile(r'.*r13.*')               
def range_reverse(start, stop):          
    for i in FuncItems(start):
        if i < start and i >= stop:
            yield i
            
ea = ScreenEA()                          
current_function = idaapi.get_func(ea)   

print("\n\n")

for inst_addr in range_reverse(ea, current_function.startEA):
    disasm_output = idc.GetDisasm(inst_addr) 
    if reg_value.findall(disasm_output):
        print("0x%X" % inst_addr, disasm_output)

#Filtering by cmp
#Output:
#('0x3AD3B', 'cmp     [esi+10h], key')
#('0x3AD43', 'cmp     edx, 10h')
#('0x3AD4E', 'cmp     byte ptr [eax+edi], 20h')
#('0x3AD54', 'cmp     edx, 10h')
#('0x3AD5F', 'cmp     byte ptr [eax+edi], 2Dh')
#('0x3AD65', 'cmp     key, 19h')
#('0x3AD6A', 'cmp     edx, 10h')
#('0x3AD80', 'cmp     al, 19h')
#('0x3AD95', 'cmp     al, dl')
#('0x3ADC4', 'cmp     edi, [esi+10h]')
#('0x3ADCD', 'cmp     key, 19h')
#('0x3AE2D', 'cmp     eax, 17h')
#('0x3AE32', 'cmp     eax, 18h')
#('0x3AE50', 'cmp     [ebp+var_3C], al')
#('0x3AFB4', 'cmp     al, byte ptr [ebp+key+xQyxXxmo]')
#('0x3AFBF', 'cmp     key, 0Ch')
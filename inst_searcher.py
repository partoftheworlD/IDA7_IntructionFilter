import idc
import idaapi
import re


class UI(object):
    def __init__(self):
        pass


class Func(object):
    def __init__(self):
        self.reg_value = re.compile(r'')
        self.stack_view = []

    def range_reverse(self, start, stop):
        for i in FuncItems(stop):
            if start > i >= stop:
                yield i

    def run(self):
        if self.stack_view:
            for j in self.stack_view:
                print "-" * 46
                current_function = idaapi.get_func(j)
                if current_function:
                    for j in [i for i in self.range_reverse(current_function.endEA, current_function.startEA)]:
                        if self.reg_value.findall(idc.GetDisasm(j)):
                            print("0x{} -- {}".format(hex(j)[2:-1].upper(), idc.GetDisasm(j)))
        else:
            print "Please input addresses to stack view buffer"
            pass


if __name__ == '__main__':
    f = Func()

    f.stack_view = [0x88b50, 0x2dca88, 0x2dc9db, 0x1d6f15,
                    0x1d71ef, 0x1c68ff, 0x1c54e4, 0x2109ed,
                    0x211a6c, 0x222499, 0x22275c, 0x277609,
                    0x2749e5, 0x276035, 0x275597]

    f.reg_value = re.compile(r'.*esi.*')
    f.run()


'''
Output:
----------------------------------------------
0x88B71 -- push    esi
0x88B8B -- pop     esi
0x88BA4 -- xor     esi, esi
0x88BB6 -- push    esi
0x88BC7 -- inc     esi
0x88BC8 -- cmp     esi, ebx
0x88BD8 -- pop     esi
0x88BF3 -- mov     esi, [esp+14h]
0x88BF9 -- and     esi, 0FF700000h
0x88BFF -- or      esi, 700000h
0x88C05 -- push    esi
0x88C1D -- push    esi
0x88C2E -- pop     esi
----------------------------------------------
0x2DC9F5 -- push    esi
0x2DC9F9 -- mov     esi, [edi+28h]
0x2DC9FC -- lea     eax, [esi+0Fh]
0x2DCA09 -- push    esi; size_t
0x2DCA29 -- lea     esi, [ecx+1]
0x2DCA2C -- cmp     esi, [edi+28h]
0x2DCA4A -- push    esi
0x2DCA55 -- mov     [edi+28h], esi
0x2DCA58 -- push    esi; size_t
0x2DCA64 -- xor     esi, esi
0x2DCA69 -- cmp     [edi+50h], esi
0x2DCA82 -- mov     eax, [eax+esi*4]
0x2DCA88 -- inc     esi
0x2DCA8C -- cmp     esi, [edi+50h]
0x2DCAB4 -- pop     esi
----------------------------------------------
0x2DC88A -- push    esi
0x2DC88B -- mov     esi, ecx
0x2DC893 -- mov     eax, [esi]
0x2DC8BF -- push    esi
0x2DC8C9 -- pop     esi
0x2DC8D1 -- movss   xmm0, dword ptr [esi+2Ch]; f_ModelBrightness
0x2DC8DE -- mov     ecx, esi
0x2DC8EA -- xor     eax, esi
0x2DC92D -- mov     eax, [esi]
0x2DC92F -- mov     ecx, esi
0x2DC95A -- mov     eax, [esi]
0x2DC961 -- mov     ecx, esi
0x2DC9AE -- xor     eax, esi
0x2DC9B0 -- mov     [esi+2Ch], eax
0x2DC9B9 -- xor     eax, esi
0x2DC9BB -- mov     [esi+30h], eax
0x2DC9BE -- test    dword ptr [esi+14h], 1000h
0x2DC9CD -- mov     eax, [esi]
0x2DC9D5 -- mov     ecx, esi
0x2DC9DC -- pop     esi
----------------------------------------------
0x1D6D39 -- push    esi
0x1D6D3A -- mov     esi, [ebp+arg_0]
0x1D6D3D -- mov     ecx, esi
0x1D6D44 -- mov     eax, [esi]
0x1D6D5C -- mov     eax, [esi]
0x1D6D5E -- mov     ecx, esi
0x1D6DCE -- lea     esi, [ebp+WideCharStr]
0x1D6DF0 -- movzx   eax, word ptr [esi]
0x1D6E00 -- movzx   eax, word ptr [esi]
0x1D6E0E -- add     esi, 2
0x1D6E11 -- cmp     word ptr [esi], 0
0x1D6E36 -- lea     esi, [ebp+var_400]
0x1D6E40 -- movzx   eax, word ptr [esi]
0x1D6E55 -- add     esi, 2
0x1D6ED6 -- mov     esi, [ebp+arg_0]
0x1D6EDF -- mov     eax, [esi]
0x1D6EE1 -- mov     ecx, esi
0x1D6EF2 -- mov     edi, [esi+18h]
0x1D6EFA -- lea     ecx, [esi+18h]
0x1D6F05 -- pop     esi
0x1D6F0C -- mov     eax, [esi+18h]
0x1D6F0F -- lea     ecx, [esi+18h]
0x1D6F17 -- pop     esi
----------------------------------------------
0x1D6F2D -- push    esi
0x1D6F38 -- pop     esi
0x1D6F59 -- mov     esi, eax
0x1D6F5B -- test    esi, esi
0x1D6F65 -- mov     eax, [esi]
0x1D6F67 -- mov     ecx, esi
0x1D6FB8 -- mov     esi, eax
0x1D6FBA -- test    esi, esi
0x1D6FC2 -- mov     eax, [esi]
0x1D6FC4 -- mov     ecx, esi
0x1D6FD5 -- mov     ecx, esi
0x1D6FE4 -- pop     esi
0x1D6FEC -- mov     eax, [esi]
0x1D7010 -- mov     eax, [esi]
0x1D7012 -- mov     ecx, esi
0x1D7029 -- pop     esi
0x1D7031 -- mov     eax, [esi]
0x1D7033 -- mov     ecx, esi
0x1D7051 -- mov     eax, [esi]
0x1D7053 -- mov     ecx, esi
0x1D706F -- lea     eax, [esi+18h]
0x1D707F -- mov     eax, [esi]
0x1D7081 -- mov     ecx, esi
0x1D7098 -- pop     esi
0x1D70A0 -- mov     eax, [esi]
0x1D70A2 -- mov     ecx, esi
0x1D70E3 -- mov     eax, [esi]
0x1D70E5 -- mov     ecx, esi
0x1D70FC -- pop     esi
0x1D7104 -- mov     eax, [esi]
0x1D7106 -- mov     ecx, esi
0x1D7144 -- mov     eax, [esi]
0x1D7146 -- mov     ecx, esi
0x1D715D -- pop     esi
0x1D71E9 -- push    esi; int
0x1D71F0 -- pop     esi
----------------------------------------------
0x1C53FA -- push    esi
0x1C5465 -- mov     esi, offset unk_7B640C
0x1C546C -- mov     [ebp+var_4], esi
0x1C5470 -- cmp     byte ptr [esi+14h], 0
0x1C547A -- mov     eax, [esi]
0x1C5482 -- mov     [esi+4], eax
0x1C5485 -- mov     eax, [esi-20h]
0x1C5488 -- mov     byte ptr [esi+14h], 1
0x1C548C -- mov     [esi+0Ch], eax
0x1C549A -- lea     edi, [esi-2034h]
0x1C54B0 -- mov     esi, offset Data
0x1C54CD -- cmovz   eax, esi
0x1C5510 -- cmovz   edx, esi
0x1C552B -- mov     esi, [ebp+var_4]
0x1C5535 -- add     esi, 204Ch
0x1C553C -- mov     [ebp+var_4], esi
0x1C553F -- cmp     esi, offset unk_7BC4F0
0x1C555E -- pop     esi
----------------------------------------------
0x210677 -- push    esi
0x2107DE -- mov     esi, ds:ThreadSleep
0x2107FD -- call    esi ; ThreadSleep
0x21080C -- call    esi ; ThreadSleep
0x21088F -- xor     esi, esi
0x210896 -- mov     [ebp+var_C], esi
0x210945 -- cvttsd2si esi, xmm1
0x210949 -- mov     [ebp+var_C], esi
0x210950 -- add     esi, dword_5900BC
0x210956 -- and     esi, 0FFFFFFFEh
0x210959 -- sub     esi, dword_5900BC
0x21095F -- mov     [ebp+var_C], esi
0x210962 -- movd    xmm0, esi
0x2109B6 -- mov     ecx, esi
0x210A3A -- mov     dword_872578, esi
0x210ADA -- test    esi, esi
0x210AEA -- lea     ebx, [esi-1]
0x210C9E -- lea     ebx, [esi-1]
0x210CB5 -- cmp     edi, esi
0x210CED -- call    sub_7FB90
0x210D0D -- test    esi, esi
0x210D17 -- mov     esi, [ecx+100Ch]
0x210D1D -- test    esi, esi
0x210D3D -- test    esi, esi
0x210D47 -- xor     esi, esi
0x210D49 -- mov     [ebp+var_10], esi
0x210D50 -- cmp     dword_8724F4[esi*4], 0
0x210D5A -- inc     esi
0x210D5B -- cmp     esi, 2
0x210D60 -- mov     [ebp+var_10], esi
0x210D63 -- cmp     esi, 2
0x210D68 -- mov     ecx, dword_8724F4[esi*4]
0x210D78 -- inc     esi
0x210D79 -- mov     [ebp+var_10], esi
0x210D7C -- cmp     esi, 2
0x210D81 -- cmp     dword_8724F4[esi*4], 0
0x210D8B -- inc     esi
0x210D8C -- mov     [ebp+var_10], esi
0x210D8F -- cmp     esi, 2
0x210DA0 -- xor     esi, esi
0x210DA2 -- cmp     [ebx+0Ch], esi
0x210DB2 -- mov     ecx, [ecx+esi*4]
0x210DBA -- inc     esi
0x210DBB -- cmp     esi, [ebx+0Ch]
0x210E15 -- lea     esi, [ecx+8]
0x210E18 -- movd    xmm0, dword ptr [esi+168h]
0x210E32 -- mov     ecx, esi
0x210E54 -- movss   xmm0, dword ptr [esi+4C9Ch]
0x210EE7 -- mov     esi, [ecx]
0x210EEE -- call    dword ptr [esi+0Ch]
0x210F71 -- mov     dword_5900C8, esi
0x210F84 -- mov     esi, ebx
0x210F86 -- lea     ebx, [esi-1]
0x211037 -- lea     ebx, [esi-1]
0x21103A -- cmp     edi, esi
0x211042 -- mov     esi, [ebp+var_C]
0x211076 -- call    sub_7FB90; STR 4# "%.2f: Starting channel %d.  %d bytes buffered, %.0fms elapsed.  (%d samples more than desired, %.0fms later than expected)" "яяяя" "Voice - chan %d, ent %d, bufsize: %d" "Voice - compress: %7.2fu, decompress: %7.2fu, gain: %7.2fu, upsample: %7.2fu, total: %7.2fu"
0x211201 -- test    esi, esi
0x211205 -- lea     ebx, [esi-1]
0x211257 -- cmp     edi, esi
0x21125E -- test    esi, esi
0x211332 -- mov     dword_872550, esi
0x2113E1 -- mov     [ebx+14h], esi
0x2115E0 -- mov     esi, [ecx+100Ch]
0x2115E6 -- test    esi, esi
0x21166F -- test    esi, esi
0x2117F9 -- mov     esi, [eax]
0x211832 -- call    dword ptr [esi+74h]
0x21192E -- mov     esi, ds:ETWMark
0x211939 -- call    esi ; ETWMark
0x211943 -- call    esi ; ETWMark
0x21194D -- call    esi ; ETWMark
0x211957 -- call    esi ; ETWMark
0x211962 -- call    esi ; ETWMark
0x21198C -- pop     esi
----------------------------------------------
0x2119AD -- push    esi
0x211A2A -- mov     esi, dword_87A6DC
0x211A30 -- mov     ecx, esi
0x211A32 -- mov     eax, [esi]
0x211A47 -- mov     eax, [esi]
0x211A49 -- mov     ecx, esi
0x211A6C -- pop     esi
0x211B23 -- pop     esi
----------------------------------------------
0x222424 -- push    esi
0x222425 -- mov     esi, ecx
0x22242F -- movss   xmm0, dword ptr [esi+420h]
0x222445 -- movss   xmm1, dword ptr [esi+420h]
0x222460 -- movss   dword ptr [esi+420h], xmm1
0x2224CE -- mov     eax, [esi+4]
0x2224DD -- lea     ecx, [esi+20h]; jumptable 102224D6 cases 0,1
0x2224E5 -- mov     dword ptr [esi], 5; jumptable 102224D6 cases 5-7
0x2224EB -- pop     esi
0x2224F0 -- mov     [esi], eax; jumptable 102224D6 cases 2,3
0x2224F2 -- pop     esi
0x2224F7 -- mov     dword ptr [esi], 4; jumptable 102224D6 default case
0x2224FD -- mov     dword ptr [esi+4], 4
0x222504 -- pop     esi; jumptable 102224D6 case 4
----------------------------------------------
0x22261A -- push    esi
0x222644 -- pop     esi
0x2226C8 -- mov     esi, [edi]
0x2226CA -- cmp     esi, 7; switch 8 cases
0x2226D3 -- jmp     ds:off_2227BC[esi*4]; switch jump
0x2227A1 -- cmp     esi, 4; jumptable 102226D3 default case
0x2227A6 -- cmp     esi, 6
0x2227AB -- cmp     esi, 7
0x2227B5 -- pop     esi
----------------------------------------------
0x2772AE -- push    esi
0x2772AF -- mov     esi, ecx
0x277391 -- fstp    qword ptr [esi+10h]
0x277406 -- movsd   xmm2, qword ptr [esi+10h]
0x27740E -- subsd   xmm0, qword ptr [esi+20h]
0x277435 -- movss   xmm1, dword ptr [esi+18h]
0x27743E -- movsd   qword ptr [esi+20h], xmm2
0x277449 -- movss   dword ptr [esi+18h], xmm1
0x277454 -- mov     ecx, esi
0x27745F -- movss   xmm0, dword ptr [esi+2Ch]
0x277464 -- subss   xmm0, dword ptr [esi+18h]
0x2774B0 -- movss   xmm0, dword ptr [esi+28h]
0x2774BB -- movss   dword ptr [esi+28h], xmm0
0x2774C1 -- pop     esi
0x277572 -- movss   xmm0, dword ptr [esi+28h]
0x277582 -- mov     eax, [esi+28h]
0x277585 -- mov     dword ptr [esi+28h], 0
0x2775F6 -- mov     eax, [esi+8]
0x2775FF -- movss   xmm1, dword ptr [esi+18h]
0x277609 -- mov     eax, [esi+0Ch]
0x27760C -- cmp     eax, [esi+8]
0x277611 -- mov     [esi+8], eax
0x277624 -- mov     eax, [esi]
0x277626 -- mov     ecx, esi
0x27763B -- mov     dword ptr [esi+18h], 0
0x277643 -- pop     esi
----------------------------------------------
0x274989 -- push    esi
0x2749B6 -- mov     esi, dword_625894
0x2749BC -- cmp     byte ptr [esi+38h], 0
0x2749EF -- mov     esi, dword_625894
0x2749F5 -- cmp     byte ptr [esi+38h], 1
0x274A3F -- pop     esi
----------------------------------------------
0x275FBE -- push    esi
0x275FBF -- mov     esi, 3
0x275FEB -- mov     eax, esi
0x275FED -- pop     esi
0x276041 -- cmovnz  esi, edx
0x276060 -- mov     eax, esi
0x276062 -- pop     esi
----------------------------------------------
0x27550A -- push    esi
0x27550F -- mov     esi, ecx
0x275590 -- mov     ecx, esi
0x2755A2 -- pop     esi
0x2755D4 -- pop     esi
'''

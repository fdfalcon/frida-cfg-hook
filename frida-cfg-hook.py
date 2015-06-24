# Written by Francisco Falcon (@fdfalcon)
# Based on an idea by deroko (@deroko_)
# Tested on 32-bit Windows 8.1 Update 3
# https://github.com/fdfalcon/frida-cfg-hook

#Dependencies:
# * pefile==1.2.10-139
# * frida==4.2.2


import sys
import frida
import pefile


def get_GuardCFCheckFunctionPointer_rva():
    ntdll = pefile.PE('C:\\Windows\\System32\\ntdll.dll')
    return ntdll.get_rva_from_offset(ntdll.DIRECTORY_ENTRY_LOAD_CONFIG.struct.get_field_absolute_offset('GuardCFCheckFunctionPointer'))


#You may want to handle incoming messages from JS code here...
def on_message(message, data):
    print "[%s] -> %s" % (message, data)


def main():
    if len(sys.argv) < 2:
        print('Usage: %s <process name or PID>' % sys.argv[0])
        sys.exit(1)

    try:
        target_process = int(sys.argv[1])
    except ValueError:
        target_process = sys.argv[1]

    guard_fptr_rva = get_GuardCFCheckFunctionPointer_rva()

    session = frida.attach(target_process)
    script = session.create_script("""
var GuardCFCheckFunctionPointer = Module.findBaseAddress('ntdll.dll').add(0x%x);
console.log('GuardCFCheckFunctionPointer: ' + GuardCFCheckFunctionPointer.toString());

/* LoadConfig.GuardCFCheckFunctionPointer -> __guard_check_icall_fptr -> guard_function
 * When CFG is enabled, __guard_check_icall_fptr points to ntdll!LrdpValidateUserCallTarget (not exported, unfortunately).
 * Otherwise, __guard_check_icall_fptr points to dummy function _guard_check_icall_nop (exported as ntdll!RtlDebugPrintTimes)
*/
var guard_function = Memory.readPointer(Memory.readPointer(GuardCFCheckFunctionPointer));
console.log('Guard function: ' + guard_function.toString());

var nop_function = Module.findExportByName('ntdll.dll', 'RtlDebugPrintTimes');
console.log('RtlDebugPrintTimes: ' + nop_function.toString());

if (guard_function.equals(nop_function)){
    console.log('[!] the instrumented program does not use Control Flow Guard!');
    console.log('[!] __guard_check_icall_fptr points to dummy function _guard_check_icall_nop.');
    send('no-cfg-enabled');
}
else{
    console.log('>> Hooking ntdll!LrdpValidateUserCallTarget...');
    Interceptor.attach(guard_function, {
        onEnter: function(args){
            console.log('[+] called from ' + this.returnAddress.sub(6).toString() + ' | validating function ptr ' + this.context.ecx);
        }
    });
}
""" % (guard_fptr_rva))
    script.on('message', on_message)
    script.load()
    raw_input("[!] Press <Enter> at any time to detach from the instrumented program.\n\n")
    session.detach()


if __name__ == '__main__':
    main()

# frida-cfg-hook
This is a sample instrumentation script based on the [Frida instrumentation toolkit](http://www.frida.re/) which leverages [Control Flow Guard](http://blogs.msdn.com/b/vcblog/archive/2014/12/08/visual-studio-2015-preview-work-in-progress-security-feature.aspx) to intercept indirect calls in CFG-enabled Windows binaries.

This is based on an idea by [@deroko_](https://twitter.com/deroko_), who first [implemented it in C](http://deroko.phearless.org/cfg_hook.zip).

This sample instrumentation script will attach to a running process and hook the **ntdll!LdrpValidateUserCallTarget** function, and every time it's called it will log the address from which it was invoked, and the function pointer that CFG is about to validate. 
Hopefully you should be able to customize it to meet your needs by modifying the Javascript part of the code. 

*frida-cfg-hook* has been tested on 32-bit Windows 8.1 Update 3.

### Usage
Just run the Python script specifying the PID or the name of the running process you want to instrument. Examples: 

```
python frida-cfg-hook.py 1234
```
or
```
python frida-cfg-hook.py calc.exe
```


### Dependencies
 * [pefile](https://github.com/erocarrera/pefile) 1.2.10-139
 * [frida](http://www.frida.re) 4.2.2

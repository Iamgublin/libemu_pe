
This project is a port of the GCC libemu project to compile with 
Visual Studio 2008

Some features have no been ported over and may not be. 

Stripped features include: profile, graphing, getpc mode

Also there have been some changes from the original. All hooks
are now implemented in application code instead of the dll. 
Actually right now this is a monolithic build. (no dll)

I will be making another project file so the dll compiles 
as stdcall and uses C exports so that it can be used from
C# and VB6

I ported this because:

1) VS debugging tools are great, (me) debugging with gcc = printf
2) I want to use it from other languages or VC code, cygwin is not safe for this
3) this lets me proxy calls to Win32 Api if i want and not redefine structs

This will be the main branch moving forward, which sadly means its days of
cross compiling are over unless you back port changes to the older build. 

See README and CHANGES for more details.

patchgen is a small tool to generate the patch files for use with the /patch
command. If you need to modify the libemu envirnoment for some reason or another
its an easy way to apply tweaks for specific shellcode. Each patch file can support
multiple patches.





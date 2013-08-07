
This project is a port of the GCC libemu project to compile with 
Visual Studio 2008

Some features have not been ported over and may not be. 

Stripped features include: profile, graphing, getpc mode

Also there have been some changes from the original. All hooks
are now implemented in application code instead of the dll. 
Actually right now this is a monolithic build. (no dll)

A project file to compile this as a stdcall dll is in the ./dll
subdirectory. This dll is compatiable with any language which can
use standard Windows dlls. Example projects are provided for C,
Visual Basic 6, and C#

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

Couple build notes.
   Be sure your project options have LIL_ENDIAN and BYTE_ORDER defined in the force
   includes. this is the /D linker command line option. It should be set already.
   The world turns upside down (well literally backwards!) with out these options set.

   Right now it is set to compile as a static build with the /MT and /MTd options
   this is so it doesnt require the external msvcr90.dll runtime which turns out
   you cant just distribute. It has to be installed which is stupid. The static
   link compiles the necessary functions into the main exe and only increases
   it size by about 300k This is still better than the 600k external runtime dll 
   anyway.

   Several other small support utilities are available in the git repository these
   include a couple tools for scdbg development as well as a patch utility for generating
   the files the /patch command uses to modify the libemu memory at runtime. 







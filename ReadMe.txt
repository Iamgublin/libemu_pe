
This project is a port of the GCC libemu project to compile with 
Visual Studio 2008

This is an early build. I know there are bugs.

Some features have no been ported over and may not be. 

Stripped features include: profile, graphing, getpc mode

Also there have been some changes from the original. All hooks
are now implemented in application code instead of the dll. 
Actually right now this is a monolithic build. (no dll)

I will be making another project file so the dll compiles 
as stdcall and uses C exports so that it can be used from
C# and VB6

It also seems to run slower than the cygwin build..this is
probably because it is still a debug build with rtti on.

I ported this because:

1) VS debugging tools are great, (me) debugging with gcc = printf
2) I want to use it from other languages or VC code, cygwin is not safe for this
3) this lets me proxy calls to Win32 Api if i want and not redefine structs

the sad thing is if i continue with this branch, it is the end of cross compiling
for the linux users :-\




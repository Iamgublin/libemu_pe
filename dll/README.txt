
This is the VS2008 project file to compile the source code
in the above directories as a _stdcall dll for use with other
programming languages.

A precompiled binary is available, but may not be frequently updated.
The main codebase does still have some printfs and such in it, so
if you decide to go this route you may want to recompile and tweak it.

The following is probably the best way to override the printfs

http://sandsprite.com/blogs/index.php?uid=11&pid=304

Also watch out in case any function types change from the main source
and the header files, exports, and declaration statements in the VB and C#
projects. 

_Minimal_ examples are provided using the Dll in VC6, Visual Basic 6, and C#

If you want to use this code, you are goign to have to still do some more work
on it to get it where you want it. These demos are just to show that its possible and
is operational right now. 




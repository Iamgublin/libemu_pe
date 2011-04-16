
patch generator is a small tool to generate files for use with the

scdbg /patch command.

each patch file can include multiple patches. 

to use it, specify the memory address as a hex string, and a hex string

representing the data you want to embed. 

I decided to do this to experiment with a couple things.

1) very easy to try out mods on the fly to the libemu envirnoment (dlls/peb etc)
2) way to apply non-permanent patchs to teh shellcode after loading but pre-execution
3) some shellcodes expect certain things in memory at time of exploitation. 


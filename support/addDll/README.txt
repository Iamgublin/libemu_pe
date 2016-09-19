
This is a small helper app i use to add new dlls and data buffers to the scdbg source.

Features are listed below.

Get HexData as C Commented Src
   This button will read in the specified file and output a hexdump and offset
   commented C source buffer. This is what I used to generate the buffer listings
   such as 

/* 7C80000 */   "\x4D\x5A\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00"   //MZ..........ÿÿ..
/* 7C80020 */   "\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"   //........@.......
/* 7C80040 */   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"   //................
/* 7C80060 */   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xC0\x00\x00\x00"   //............À...
/* 7C80080 */   "\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21\x54\x68"   //.......Í!..LÍ!Th

   note this can be very slow on large files because of the way i add it to teh UI
   it would be easy to speed up, but most buffers are small so who cares for this.

   Note that the offset used is taken from the startr address you provide in the
   base textbox.


Prepare raw lordPE Export list
   This button will read in the file specified which is expected to be a 
   raw export table listing from lordpe such as the following:

   0x0001  0x00059D2B "PropertyLengthAsVariant"
   0x0002  0x00059C93 "RtlConvertPropertyToVariant"
   0x0003  0x00059BF5 "RtlConvertVariantToProperty"
   0x0004  0x00002AD0 "RtlInterlockedPushListSList"
   0x0005  0x00002B30 "RtlUlongByteSwap"
   0x0006  0x00002B40 "RtlUlonglongByteSwap"
   0x0007  0x00002B20 "RtlUshortByteSwap"

   it will generate the output used in for the exports hooks array

   {"PropertyLengthAsVariant", 0x00059D2B, NULL, NULL},
   {"RtlConvertPropertyToVariant", 0x00059C93, NULL, NULL},
   {"RtlConvertVariantToProperty", 0x00059BF5, NULL, NULL},
   {"RtlInterlockedPushListSList", 0x00002AD0, NULL, NULL},
   {"RtlUlongByteSwap", 0x00002B30, NULL, NULL},
   {"RtlUlonglongByteSwap", 0x00002B40, NULL, NULL},

Additionally for every dll you add, it helps to compile stats such as the following

Executable modules, item 12
 Base=77DD0000
 Size=0009B000

 export table rva = 16A4 size = 5252  va = 77dd16A4, foff 16a4  

.segment = advapi32_77DD0000,
.segment = advapi32_77dd16A4,


const char advapi32_77DD0000[] =
const char advapi32_77dd16A4[] =

struct emu_env_w32_dll_export advapi32_exports[] = 
{

{0,0,NULL},
};


You will also have to use pebbuilder to then build a new peb to embed. add the exports to
the exports listing, and teh mem buffer segments etc. Its a little bit of work, but
its actually not that bad.




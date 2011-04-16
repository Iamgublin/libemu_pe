typedef unsigned long  uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char  uint8_t;

struct emu_env_w32_known_dll
{
	const char *dllname;
	uint32_t 	baseaddress;
	uint32_t	imagesize;
};

	typedef struct _LIST
	{
		uint32_t Flink;
		uint32_t Blink;
	} mLIST;

	typedef struct _UNICODE_STRING
	{
		uint16_t Length;
		uint16_t MaximumLength;
		uint32_t Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;

	typedef struct _LDR
	{
		/* 0x00 */ mLIST InLoadOrder;
		//            4 byte Forward Link
		//            4 byte Backward Link
		/* 0x08 */ mLIST InMemOrder;
		/* 0x10 */ mLIST InInitOrder;
		/* 0x18 */ uint32_t DllBase;
		/* 0x1c */ uint32_t EntryPoint;
		/* 0x1f */ uint32_t Reserved;           
		/* 0x24 */ UNICODE_STRING FullDllName;
		//            2 byte Length
		//            2 Byte MaxLength
		//            4 byte pointer to Unicode string
		/* 0x2c */ UNICODE_STRING BaseDllName;
	} LDR;

		// http://www.nirsoft.net/kernel_struct/vista/PEB_LDR_DATA.html
	typedef struct _PEB
	{
		 /* 0x00 */ uint32_t Length;
		 /* 0x04 */ uint8_t Initialized[4];
		 /* 0x08 */ uint32_t SsHandle;
		 /* 0x0c */ mLIST InLoadOrder;
		 /* 0x14 */ mLIST InMemOrder;
		 /* 0x1c */ mLIST InInitOrder;
		 /* 0x24 */ uint8_t EntryInProgress;
	} PEB;





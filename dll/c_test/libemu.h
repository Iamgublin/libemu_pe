
typedef long            int32_t;
typedef long            int_least32_t;
typedef long            int_fast32_t;
typedef unsigned long   uint32_t;
typedef unsigned long   uint_least32_t;
typedef unsigned long   uint_fast32_t;

typedef unsigned char   uint8_t;
typedef char            int8_t;
typedef unsigned short  uint16_t;
typedef short			int16_t;

typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;

typedef int _Bool;

#define size_t unsigned long

typedef void (*mm_callback)(uint32_t);
typedef void (*mm_range_callback)(char, char, uint32_t);
typedef void (*emu_log_logcb)(struct emu *e, enum emu_log_level level, const char *msg);
//typedef void (*genericApi_callback)(emu_env_w32_dll_export*);

enum emu_reg32 { eax = 0, ecx, edx, ebx, esp, ebp, esi, edi};
enum emu_reg16{  ax =  0, cx, dx, bx, sp, bp, si, di };
enum emu_reg8 {  al=0,cl, dl, bl,ah, ch, dh, bh };
enum emu_segment { s_cs = 0, s_ss, s_ds, s_es, s_fs, s_gs};
enum emu_cpu_debug_flag { instruction_string = 0, instruction_size = 1,};
enum emu_log_level{	EMU_LOG_NONE,	EMU_LOG_INFO,	EMU_LOG_DEBUG};

enum emu_env_type
{
	emu_env_type_win32,
	//emu_env_type_linux,
};


struct emu_logging
{
	enum emu_log_level loglevel;
	emu_log_logcb logcb;
};

struct emu_memory
{
	struct emu *emu;
	void ***pagetable;
	
	uint32_t segment_offset;
	enum emu_segment segment_current;
	
	uint32_t segment_table[6];

	bool read_only_access;
};

struct emu_fpu_instruction
{
	uint16_t prefixes;
	
	uint8_t fpu_data[2]; /* TODO: split into correct fields */
	uint32_t ea;
	
	uint32_t last_instr;

};

struct emu_tracking_info
{
	uint32_t eip;

	uint32_t eflags;
	uint32_t reg[8];

	uint8_t fpu:1; // used to store the last_instruction information required for fnstenv
};

struct emu_cpu_instruction
{
	uint8_t opc;
	uint8_t opc_2nd;
	uint16_t prefixes;
	uint8_t s_bit : 1;
	uint8_t w_bit : 1;
	uint8_t operand_size : 2;

	struct /* mod r/m data */
	{
		union
		{
			uint8_t mod : 2;
			uint8_t x : 2;
		};

		union
		{
			uint8_t reg1 : 3;
			uint8_t opc : 3;
			uint8_t sreg3 : 3;
			uint8_t y : 3;
		};

		union
		{
			uint8_t reg : 3;
			uint8_t reg2 : 3;
			uint8_t rm : 3;
			uint8_t z : 3;
		};

		struct
		{
			uint8_t scale : 2;
			uint8_t index : 3;
			uint8_t base : 3;
		} sib;

		union
		{
			uint8_t s8;
			uint16_t s16;
			uint32_t s32;
		} disp;
		
		uint32_t ea;
	} modrm;

	uint32_t imm;
	uint16_t *imm16;
	uint8_t *imm8;

	int32_t disp;


};

struct emu_instruction
{
	uint16_t prefixes;
	uint8_t opc;
	uint8_t is_fpu : 1;
	
	union
	{
		struct emu_cpu_instruction cpu;
		struct emu_fpu_instruction fpu;
	};

	struct  /*looks like this is found source graphing support..*/
	{
		struct emu_tracking_info init;
		struct emu_tracking_info need;		
	} track;

	struct 
	{
		uint8_t has_cond_pos : 1;
		uint32_t norm_pos;
		uint32_t cond_pos;
	} source;
};

struct emu_track_and_source
{
	struct emu_tracking_info track;
	//struct emu_hashtable    *static_instr_table;
	//struct emu_hashtable    *run_instr_table;
	uint32_t static_instr_table; //actually pointers to structures, but I dont want to fuck with the struct now
	uint32_t run_instr_table;	
};



struct emu_cpu
{
	struct emu *emu;
	struct emu_memory *mem;
	bool repeat_current_instr;
	uint32_t debugflags;

	uint32_t eip;
	uint32_t eflags;
	uint32_t reg[8];
	uint16_t *reg16[8];
	uint8_t *reg8[8];

	struct emu_instruction 			instr;
	struct emu_cpu_instruction_info 	*cpu_instr_info;
	
	uint32_t last_fpu_instr[2];

	char *instr_string;

	

	struct emu_track_and_source *tracking;
};



struct emu
{
	struct emu_logging *log;
	struct emu_memory *memory; 
	struct emu_cpu *cpu;

	int 	errornum;
	char 	*errorstr;
};


struct emu_env_w32_dll_export
{
	char 		*fnname;
	uint32_t 	virtualaddr;
    int32_t		(__stdcall *fnhook)(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
	void 		*userdata;
	uint32_t	ordial;
	//uint32_t	(*userhook)(struct emu_env *env, struct emu_env_hook *hook, ...);
};


struct emu_env_w32_dll
{
	char 		*dllname;

	char 		*image;
	uint32_t	imagesize;

	uint32_t	baseaddr;

	struct emu_env_w32_dll_export *exportx;
	/* std::hash_map<uint32_t, void*>    */ void *exports_by_fnptr;    //havent done the hashtable defs yet in this .h
	/* std::hash_map<std::string, void*> */ void *exports_by_fnname;
	/* std::hash_map<uint32_t, void*>    */ void *exports_by_ordial;
};

struct emu_env_w32
{
	struct emu *emu;
	struct emu_env_w32_dll **loaded_dlls;
	uint32_t	baseaddr;
	char*		lastApiCalled;   //used for filtering spammy calls dzzie 5.18.11
	uint32_t    lastApiHitCount;
};

struct emu_env
{
	struct emu_env_w32   *win;
	struct emu *emu;
	void *userdata;
};



struct emu_cpu_instruction_info
{
	int32_t (*function)(struct emu_cpu *, struct emu_cpu_instruction *);
	const char *name;
    
	struct
	{
		uint8_t s_bit : 1;
		uint8_t w_bit : 1;
		uint8_t modrm_byte : 4;
		uint8_t imm_data : 3;
		uint8_t disp_data : 3;
		uint8_t level : 2;
		uint8_t type : 2;
		uint8_t fpu_info : 1;
	} format;
};
/*
struct emu_track_and_source
{
	struct emu_tracking_info track;

	//struct emu_graph        *static_instr_graph;
	struct emu_hashtable    *static_instr_table;

	//struct emu_graph        *run_instr_graph;
	struct emu_hashtable    *run_instr_table;
	
};
*/
/*
struct emu_tracking_info
{
	uint32_t eip;

	uint32_t eflags;
	uint32_t reg[8];

	uint8_t fpu:1; // used to store the last_instruction information required for fnstenv
};
*/

struct emu_string
{
    uint32_t    size;
    void        *data;
	uint32_t	allocated;

};


//extern "C"{

struct emu *emu_new(void);
void emu_free(struct emu *e);
struct emu_memory *emu_memory_get(struct emu *e);
struct emu_logging *emu_logging_get(struct emu *e);
struct emu_cpu *emu_cpu_get(struct emu *e);
void emu_errno_set(struct emu *e, int err);
int emu_errno(struct emu *c);
void emu_strerror_set(struct emu *e, const char *format, ...);
const char *emu_strerror(struct emu *e);
struct emu_cpu *emu_cpu_new(struct emu *e);
uint32_t emu_cpu_reg32_get(struct emu_cpu *cpu_p, enum emu_reg32 reg);
void emu_cpu_reg32_set(struct emu_cpu *cpu_p, enum emu_reg32 reg, uint32_t val);
uint16_t emu_cpu_reg16_get(struct emu_cpu *cpu_p, enum emu_reg16 reg);
void emu_cpu_reg16_set(struct emu_cpu *cpu_p, enum emu_reg16 reg, uint16_t val);
uint8_t emu_cpu_reg8_get(struct emu_cpu *cpu_p, enum emu_reg8 reg);
void emu_cpu_reg8_set(struct emu_cpu *cpu_p, enum emu_reg8 reg, uint8_t val);
uint32_t emu_cpu_eflags_get(struct emu_cpu *c);
void emu_cpu_eflags_set(struct emu_cpu *c, uint32_t val);
void emu_cpu_eip_set(struct emu_cpu *c, uint32_t eip);
uint32_t emu_cpu_eip_get(struct emu_cpu *c);
int32_t emu_cpu_parse(struct emu_cpu *c);
int32_t emu_cpu_step(struct emu_cpu *c);
int32_t emu_cpu_run(struct emu_cpu *c, uint32_t limit);
void emu_cpu_free(struct emu_cpu *c);
void emu_cpu_debug_print(struct emu_cpu *c);
void emu_cpu_debugflag_set(struct emu_cpu *c, uint8_t flag);
void emu_cpu_debugflag_unset(struct emu_cpu *c, uint8_t flag);
uint32_t emu_disasm_addr(struct emu_cpu *c, uint32_t eip, char *str);
struct emu_env *emu_env_new(struct emu *e);
void emu_env_free(struct emu_env *env);
struct emu_env_w32 *emu_env_w32_new(struct emu *e);
void emu_env_w32_free(struct emu_env_w32 *env);
int32_t emu_env_w32_load_dll(struct emu_env_w32 *env, char *path);

int32_t emu_env_w32_export_new_hook(struct emu_env *env,
								const char *exportname, 
								int32_t (__stdcall *fnhook)(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex),
								void *userdata);


struct emu_env_w32_dll_export *emu_env_w32_eip_check(struct emu_env *env);
struct emu_env_w32_dll *emu_env_w32_dll_new(void);
void emu_env_w32_dll_free(struct emu_env_w32_dll *dll);
void emu_env_w32_dll_exports_copy(struct emu_env_w32_dll *to, struct emu_env_w32_dll_export *from);
struct emu_env_w32_dll_export *emu_env_w32_dll_export_new(void);
void emu_env_w32_dll_export_copy(struct emu_env_w32_dll_export *to, struct emu_env_w32_dll_export *from);
void emu_env_w32_dll_export_free(struct emu_env_w32_dll_export *exp);

extern struct emu_logging *emu_logging_get(struct emu *e);
struct emu_logging *emu_log_new(void);
void emu_log_free(struct emu_logging *el);
void emu_log_level_set(struct emu_logging *el, enum emu_log_level level);
void emu_log(struct emu *e, enum emu_log_level level, const char *format, ...);
void emu_log_set_logcb(struct emu_logging *el, emu_log_logcb logcb);
void emu_log_default_logcb(struct emu *e, enum emu_log_level level, const char *msg);
void logDebug(struct emu* e, const char* format, ...);
void* bcopy (void* src, void* dest, unsigned int len);
struct emu_memory *emu_memory_new(struct emu *e);
void emu_memory_clear(struct emu_memory *em);
void emu_memory_free(struct emu_memory *em);

/* read access, these functions return -1 on error  */
int32_t emu_memory_read_byte(struct emu_memory *m, uint32_t addr, uint8_t *byte);
int32_t emu_memory_read_block(struct emu_memory *m, uint32_t addr, void *dest, size_t len);
int32_t emu_memory_read_word(struct emu_memory *m, uint32_t addr, uint16_t *word);
int32_t emu_memory_read_dword(struct emu_memory *m, uint32_t addr, uint32_t *dword);
int32_t emu_memory_read_string(struct emu_memory *m, uint32_t addr, struct emu_string *s, uint32_t maxsize);

/* write access */
int32_t emu_memory_write_byte(struct emu_memory *m, uint32_t addr, uint8_t byte);
int32_t emu_memory_write_block(struct emu_memory *m, uint32_t addr, void *src, size_t len);
int32_t emu_memory_write_word(struct emu_memory *m, uint32_t addr, uint16_t word);
int32_t emu_memory_write_dword(struct emu_memory *m, uint32_t addr, uint32_t dword);

/* segment selection */
void emu_memory_segment_select(struct emu_memory *m, enum emu_segment s);
enum emu_segment emu_memory_segment_get(struct emu_memory *m);

/* alloc */
int32_t emu_memory_alloc(struct emu_memory *m, uint32_t *addr, size_t len);
/*int32_t emu_memory_alloc_at(struct emu_memory *m, uint32_t addr, size_t len);*/

/* information */
uint32_t emu_memory_get_usage(struct emu_memory *m);

void emu_memory_mode_ro(struct emu_memory *m);
void emu_memory_mode_rw(struct emu_memory *m);

/* memory access hook -dzzie */
void emu_memory_set_access_monitor(uint32_t lpfnCallback);
void emu_memory_add_monitor_point(uint32_t address);
void emu_memory_add_monitor_range(char id, uint32_t start_at, uint32_t end_at);
void emu_memory_set_range_access_monitor(uint32_t lpfnCallback);

struct emu_string *emu_string_new(void);
void emu_string_free(struct emu_string *s);
char *emu_string_char(struct emu_string *s);
void emu_string_append_char(struct emu_string *s, const char *data);
void emu_string_append_format(struct emu_string *s, const char *format, ...);

//void emu_env_w32_generic_api_handler(uint32_t lpfnCallback);

//}

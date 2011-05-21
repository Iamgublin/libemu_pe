#include <windows.h>

struct run_time_options
{
	int opts_parsed;
	int cur_step;
	int verbose;
	uint32_t steps;
	unsigned char *scode;
	uint32_t size;
	uint32_t offset;
	bool file_mode;
	bool getpc_mode;
	char sc_file[500];
	bool dump_mode;
	int interactive_hooks;
	int  log_after_va;
	int  log_after_step;
	int  verbosity_after;
	int  verbosity_onerr;
	bool exec_till_ret;
	int  time_delay;
	bool show_hexdumps;
	char* break_at_instr;
	bool  mem_monitor;
	bool  mem_monitor_dlls;
	bool  no_color;
	int   hexdump_file;
	int   disasm_mode;
	uint32_t step_over_bp;
	char* fopen_fpath;
	uint32_t fopen_fsize;
	HANDLE h_fopen;
	int	  adjust_getfsize;
	bool  report;
	bool  break0;
	uint32_t break_above;
	char* patch_file;
	char* scan_dir;
	bool  CreateFileOverride;
	char* cmdline;
	char* apiLookUpMode;

	struct 
	{
		struct
		{
			char *host;
			int port;
		}connect;

	}override;

};

struct mmm_point{
	uint32_t address;
	char* name;
	uint32_t hitat;
};

struct mmm_range{
	char id;
	char* name;
	uint32_t start_at;
	uint32_t end_at;
};

struct patch{
	char memAddress[8];
	uint32_t dataSize;
	uint32_t dataOffset;
};

extern struct mmm_point mm_points[];
extern struct mmm_range mm_ranges[];
extern struct run_time_options opts;

bool cmp(void *a, void *b);
uint32_t hash(void *key);
bool string_cmp(void *a, void *b);
uint32_t string_hash(void *key);



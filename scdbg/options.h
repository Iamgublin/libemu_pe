
struct run_time_options
{
	int cur_step;
	int verbose;
	uint32_t steps;
	char *graphfile;
	bool from_stdin;
	unsigned char *scode;
	uint32_t size;
	uint32_t offset;
	bool file_mode;
	char sc_file[500];
	bool dump_mode;
	int interactive_hooks;
	bool adjust_offsets;
	int  log_after_va;
	int  log_after_step;
	int  verbosity_after;
	int  verbosity_onerr;
	bool exec_till_ret;
	int  time_delay;
	bool show_hexdumps;
	char* break_at_instr;
	bool  getpc_mode;
	int   org_getpc;
	bool  mem_monitor;
	bool  mem_monitor_dlls;
	bool  no_color;
	int   hexdump_file;
	int   disasm_mode;
	uint32_t step_over_bp;
	FILE *fopen;
	int	  adjust_getfsize;
	bool  report;

	struct 
	{
		struct
		{
			char *host;
			int port;
		}connect;

	}override;

};

struct mm_point{
	uint32_t address;
	char* name;
	uint32_t hitat;
};

struct mm_range{
	char id;
	char* name;
	uint32_t start_at;
	uint32_t end_at;
};

extern struct mm_point mm_points[];
extern struct mm_range mm_ranges[];
extern struct run_time_options opts;

bool cmp(void *a, void *b);
uint32_t hash(void *key);
bool string_cmp(void *a, void *b);
uint32_t string_hash(void *key);



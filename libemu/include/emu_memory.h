/********************************************************************************
 *                               libemu
 *
 *                    - x86 shellcode emulation -
 *
 *
 * Copyright (C) 2007  Paul Baecher & Markus Koetter
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * 
 * 
 *             contact nepenthesdev@users.sourceforge.net  
 *
 *******************************************************************************/

#ifndef HAVE_EMU_MEMORY_H
#define HAVE_EMU_MEMORY_H

#include <inttypes.h>
//#include <sys/types.h>

#define size_t unsigned long

enum emu_segment {
	s_cs = 0, s_ss, s_ds, s_es, s_fs, s_gs
};

struct emu;
struct emu_memory;
struct emu_string;

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
int32_t emu_memory_read_wide_string(struct emu_memory *m, uint32_t addr, struct emu_string *s, uint32_t maxsize); //dz 6.24.11
int32_t emu_memory_read_wide_string_to_buf(struct emu_memory *m, uint32_t addr, char* buf, uint32_t maxsize);     //dz 6.12.15
unsigned char* emu_memory_read_block_a(struct emu_memory *m, uint32_t addr, size_t len); //dz 4.25.13

/* write access */
int32_t emu_memory_write_byte(struct emu_memory *m, uint32_t addr, uint8_t byte);
int32_t emu_memory_write_block(struct emu_memory *m, uint32_t addr, void *src, size_t len);
int32_t emu_memory_write_word(struct emu_memory *m, uint32_t addr, uint16_t word);
int32_t emu_memory_write_dword(struct emu_memory *m, uint32_t addr, uint32_t dword);

/* segment selection */
void emu_memory_segment_select(struct emu_memory *m, enum emu_segment s);
enum emu_segment emu_memory_segment_get(struct emu_memory *m);

//dzzie 4.10.13
void emu_memory_segment_setval(struct emu_memory *m, enum emu_segment s, uint32_t val);
uint32_t emu_memory_segment_getval(struct emu_memory *m, enum emu_segment s);


/* alloc */
int32_t emu_memory_alloc(struct emu_memory *m, uint32_t *addr, size_t len);
/*int32_t emu_memory_alloc_at(struct emu_memory *m, uint32_t addr, size_t len);*/

/* information  */
uint32_t emu_memory_get_usage(struct emu_memory *m);

void emu_memory_mode_ro(struct emu_memory *m);
void emu_memory_mode_rw(struct emu_memory *m);

/* memory access hook -dzzie */
void emu_memory_set_access_monitor(uint32_t lpfnCallback);
void emu_memory_add_monitor_point(uint32_t address);
void emu_memory_add_monitor_range(char id, uint32_t start_at, uint32_t end_at);
void emu_memory_set_range_access_monitor(uint32_t lpfnCallback);

void* mytranslate_addr(struct emu_memory *em, uint32_t addr);
//----------------------------

#define MEM_BYTE_READ(cpu_p, addr, data_p) \
 { int32_t ret = emu_memory_read_byte((cpu_p)->mem, addr, data_p); \
 if( ret != 0 ) \
  return ret; }

#define MEM_BYTE_WRITE(cpu_p, addr, data) \
 { int32_t ret = emu_memory_write_byte((cpu_p)->mem, addr, data); \
 if( ret != 0 ) \
  return ret; }

#define MEM_WORD_READ(cpu_p, addr, data_p) \
 { int32_t ret = emu_memory_read_word((cpu_p)->mem, addr, data_p); \
 if( ret != 0 ) \
  return ret; }

#define MEM_WORD_WRITE(cpu_p, addr, data) \
 { uint16_t val; \
 bcopy(&(data), &val, 2); \
 int32_t ret = emu_memory_write_word((cpu_p)->mem, addr, val); \
 if( ret != 0 ) \
  return ret; }

#define MEM_DWORD_READ(cpu_p, addr, data_p) \
 { int32_t ret = emu_memory_read_dword((cpu_p)->mem, addr, data_p); \
 if( ret != 0 ) \
  return ret; }

#define MEM_DWORD_WRITE(cpu_p, addr, data) \
 { uint32_t val; \
 bcopy(&(data), &val, 4); \
 int32_t ret = emu_memory_write_dword((cpu_p)->mem, addr, val); \
 if( ret != 0 ) \
  return ret; }


#endif // HAVE_EMU_MEMORY_H

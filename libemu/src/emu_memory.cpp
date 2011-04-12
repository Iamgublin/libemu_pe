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

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>

#include "emu/emu.h"
#include "emu/emu_log.h"
#include "emu/emu_memory.h"
#include "emu/emu_string.h"
#include "emu/emu_hashtable.h"

#define PAGE_BITS 12 /* size of one page, 2^12 = 4096 */
#define PAGESET_BITS 10 /* number of pages in one pageset, 2^10 = 1024 */


#define PAGE_SIZE (1 << PAGE_BITS)
#define PAGESET_SIZE (1 << PAGESET_BITS)

#define PAGESET(x) ((x) >> (PAGESET_BITS + PAGE_BITS))
#define PAGE(x) (((x) >> PAGE_BITS) & ((1 << PAGESET_BITS) - 1))
#define OFFSET(x) (((1 << PAGE_BITS) - 1) & (x))

#define FS_SEGMENT_DEFAULT_OFFSET 0x7ffdf000

//------------  dzzie -------------- experiment to see how useful this is...
typedef void (*mm_callback)(uint32_t);
mm_callback mem_monitor_callback=0;

typedef void (*mm_range_callback)(char, char, uint32_t);
mm_range_callback mem_monitor_range_callback=0;

int mm_points[256];
int mm_point_cnt=0;
int mm_range_cnt=0;

struct mm_range{
	char id;
	uint32_t start_at;
	uint32_t end_at;
};

struct mm_range mm_ranges[256];

//----------------------------------

struct emu_memory
{
	struct emu *emu;
	void ***pagetable;
	
	uint32_t segment_offset;
	enum emu_segment segment_current;
	
	uint32_t segment_table[6];

	bool read_only_access;
};

#if 1
/*static void emu_memory_debug_pagetable(struct emu_memory *m)
{
	int pagesets = 1 << (32 - PAGESET_BITS - PAGE_BITS);
	int pagesets_used = 0;
	
	printf("*** memory debug\n");
	
	int i, j;
	
	for( i = 0; i < pagesets; i++ )
	{
		if( m->pagetable[i] != NULL )
		{
			printf("  pageset %d allocated at 0x%08x\n", i, (int)m->pagetable[i]);
			int pages = 1 << (PAGESET_BITS);
			int pages_used = 0;

			for( j = 0; j < pages; j++ )
			{
				if( m->pagetable[i][j] != NULL )
				{
					printf("    page %d allocated at 0x%08x\n", j, (int)m->pagetable[i][j]);
					pages_used++;
				}
			}
			
			printf("    %d/%d pages used\n", pages_used, pages);
			
			pagesets_used++;
		}
	}
	
	printf("  %d/%d pagesets used\n", pagesets_used, pagesets);
	printf("*** end of memory debug\n");
}

static void emu_memory_debug_addr(uint32_t addr)
{
	printf("addr 0x%08x, pageset 0x%08x, page 0x%08x, offset 0x%08x\n",
		addr, PAGESET(addr), PAGE(addr), OFFSET(addr));
}*/
#endif

uint32_t emu_memory_get_usage(struct emu_memory *m)
{
	uint32_t usage = (1 << (32 - PAGE_BITS - PAGESET_BITS)) * sizeof(void *); /* pageset table */
	int pagesets = 1 << (32 - PAGESET_BITS - PAGE_BITS);
	
	int i, j;
	
	for( i = 0; i < pagesets; i++ )
	{
		if( m->pagetable[i] != NULL )
		{
			usage += PAGESET_SIZE * sizeof(void *);
			int pages = 1 << (PAGESET_BITS);

			for( j = 0; j < pages; j++ )
				if( m->pagetable[i][j] != NULL )
					usage += PAGE_SIZE;
		}
	}
	
	return usage;
}

struct emu_memory *emu_memory_new(struct emu *e)
{
	struct emu_memory *em = (struct emu_memory *)malloc(sizeof(struct emu_memory));
	if( em == NULL )
	{
		return NULL;
	}
	memset(em, 0, sizeof(struct emu_memory));
	
	em->emu = e;
	
	em->pagetable = malloc((1 << (32 - PAGE_BITS - PAGESET_BITS)) * sizeof(void *));
	if( em->pagetable == NULL )
	{
		return NULL;
	}
	memset(em->pagetable, 0, (1 << (32 - PAGE_BITS - PAGESET_BITS)) * sizeof(void *));
	
	em->segment_table[s_fs] = FS_SEGMENT_DEFAULT_OFFSET;

	em->read_only_access = false;

	return em;
}

void emu_memory_free(struct emu_memory *m)
{
	int i, j;
	
	for( i = 0; i < (1 << (32 - PAGESET_BITS - PAGE_BITS)); i++ )
	{
		if( m->pagetable[i] != NULL )
		{
			for( j = 0; j < PAGESET_SIZE; j++ )
				if( m->pagetable[i][j] != NULL )
					free(m->pagetable[i][j]);
			
			free(m->pagetable[i]);
		}
	}
	
	free(m->pagetable);
	free(m);
}

void emu_memory_clear(struct emu_memory *m)
{
	int i, j;
	
	for( i = 0; i < (1 << (32 - PAGESET_BITS - PAGE_BITS)); i++ )
	{
		if( m->pagetable[i] != NULL )
		{
			for( j = 0; j < PAGESET_SIZE; j++ )
				if( m->pagetable[i][j] != NULL )
					free(m->pagetable[i][j]);
			
			free(m->pagetable[i]);
		}
	}

	memset(m->pagetable, 0, (1 << (32 - PAGE_BITS - PAGESET_BITS)) * sizeof(void *));
	
	m->segment_table[s_fs] = FS_SEGMENT_DEFAULT_OFFSET;

	m->read_only_access = false;
}

static inline int page_is_alloc(struct emu_memory *em, uint32_t addr)
{
	if( em->pagetable[PAGESET(addr)] != NULL )
	{
		if( em->pagetable[PAGESET(addr)][PAGE(addr)] != NULL )
		{
			return -1;
		} 
	}
	
	return 0;
}

static inline int page_alloc(struct emu_memory *em, uint32_t addr)
{
	if( em->pagetable[PAGESET(addr)] == NULL )
	{
		em->pagetable[PAGESET(addr)] = malloc(PAGESET_SIZE * sizeof(void *));
		
		if( em->pagetable[PAGESET(addr)] == NULL )
		{
			emu_errno_set(em->emu, ENOMEM);
			emu_strerror_set(em->emu, "out of memory\n", addr);
			return -1;
		}
		
		memset(em->pagetable[PAGESET(addr)], 0, PAGESET_SIZE * sizeof(void *));
	}

	if( em->pagetable[PAGESET(addr)][PAGE(addr)] == NULL )
	{
		em->pagetable[PAGESET(addr)][PAGE(addr)] = malloc(PAGE_SIZE);
		
		if( em->pagetable[PAGESET(addr)][PAGE(addr)] == NULL )
		{
			emu_errno_set(em->emu, ENOMEM);
			emu_strerror_set(em->emu, "out of memory\n", addr);
			return -1;
		}
		memset(em->pagetable[PAGESET(addr)][PAGE(addr)], 0, PAGE_SIZE);
	}

	return 0;
}

static inline void *translate_addr(struct emu_memory *em, uint32_t addr)
{
	if( em->pagetable[PAGESET(addr)] != NULL )
	{
		if( em->pagetable[PAGESET(addr)][PAGE(addr)] != NULL )
		{
			return em->pagetable[PAGESET(addr)][PAGE(addr)] + OFFSET(addr);
		}
	}
	
	return NULL;
}

void mm_check(uint32_t addr, uint32_t len, char mode){
	
	int i=0;

	//if(mode=='w') printf("Write: %x %x\n",addr,len);

	if( (int)mem_monitor_callback != 0){

		for(i=0; i<mm_point_cnt; i++){
			if( mm_points[i] >= addr && mm_points[i] <= (addr + len) ){
			//if( mm_points[i] == addr ){
				mem_monitor_callback(addr);
			}
		}

	}

	if( (int)mem_monitor_range_callback != 0){

		for(i=0; i<mm_range_cnt; i++){
			if( addr >= mm_ranges[i].start_at && addr <= mm_ranges[i].end_at ){ //directly in range
				mem_monitor_range_callback(mm_ranges[i].id, mode, addr);
				break;
			}
			if(addr < mm_ranges[i].start_at){ //check range
				if( (addr + len) >= mm_ranges[i].start_at){	
					mem_monitor_range_callback(mm_ranges[i].id, mode, addr);
					break;
				}
			}
		}

	}

}

int32_t emu_memory_read_byte(struct emu_memory *m, uint32_t addr, uint8_t *byte)
{
	addr += m->segment_offset;
	void *address = translate_addr(m, addr);
	
	mm_check(addr,1,'r');

	if( address == NULL )
	{
		emu_errno_set(m->emu, EFAULT);
		emu_strerror_set(m->emu, "error accessing 0x%08x not mapped\n", addr);
		return -1;
	}
	
	*byte = *((uint8_t *)address);
	
	return 0;
}

int32_t emu_memory_read_word(struct emu_memory *m, uint32_t addr, uint16_t *word)
{
#if BYTE_ORDER == BIG_ENDIAN
	uint16_t val;
	int32_t retval = emu_memory_read_block(m, addr, &val, 2);
	val =  ((val & 0xff00) >> 8) | 
		   ((val & 0x00ff) << 8);
	bcopy(&val,word,2);
	return retval;
#else
	return emu_memory_read_block(m, addr, word, 2);
#endif
}

int32_t emu_memory_read_dword(struct emu_memory *m, uint32_t addr, uint32_t *dword)
{
#if BYTE_ORDER == BIG_ENDIAN
	uint32_t val;
	int32_t retval =  emu_memory_read_block(m, addr, &val, 4);
	val =  ((val & (0xff000000)) >> 24) | 
		   ((val & (0x00ff0000)) >> 8)  | 
		   ((val & (0x0000ff00)) << 8) | 
		   ((val & (0x000000ff)) << 24);
	memcpy(dword, &val, 4);
	return retval;
#else
	return emu_memory_read_block(m, addr, dword, 4);
#endif
}

int32_t emu_memory_read_block(struct emu_memory *m, uint32_t addr, void *dest, size_t len)
{
	uint32_t oaddr = addr; /* save original addr for recursive call */
	addr += m->segment_offset;
	
	mm_check(addr,len,'r');

	void *address = translate_addr(m, addr);
	
	if( address == NULL )
	{
		emu_errno_set(m->emu, EFAULT);
		emu_strerror_set(m->emu, "error accessing 0x%08x not mapped\n", addr);
		return -1;
	}

	if (OFFSET(addr) + len <= PAGE_SIZE)
	{
		bcopy(address, dest, len);
		return 0;
	}
	else
	{
		uint32_t cb = PAGE_SIZE - OFFSET(addr);
		bcopy(address, dest, cb);
		return emu_memory_read_block(m, oaddr + cb, dest + cb, len - cb);
	}
}
/* original
int32_t emu_memory_read_string(struct emu_memory *m, uint32_t addr, struct emu_string *s, uint32_t maxsize)
{
	uint32_t i = 0;
	
	void *address;
	
	while( 1 )
	{
		if (i > maxsize - 1)
			return -1;
		
		address = translate_addr(m, addr + i);

		if( address == NULL )
			return -1;

		if( *(uint8_t *)address == '\0' )
			break;

		i++;
	}

	s->data = malloc(i + 1);
	memset(s->data, 0, i + 1);
	s->size = i;

	return emu_memory_read_block(m, addr, s->data, i);
}*/

//modified so that even if it fails it still returns an empty string..makes logging easier.. -dzzie 3.10.11
int32_t emu_memory_read_string(struct emu_memory *m, uint32_t addr, struct emu_string *s, uint32_t maxsize)
{
	uint32_t i = 0;
	
	void *address;
	
	while( 1 )
	{
		if (i > maxsize - 1) return -1;
		address = translate_addr(m, addr + i);
		if( address == NULL ) break;
		if( *(uint8_t *)address == '\0' ) break;
		i++;
	}

	if(address == NULL){
		s->data = malloc(4);
		strcpy(s->data, "");
		s->size = 0;
		return 0;
	}else{
		s->data = malloc(i + 1);
		memset(s->data, 0, i + 1);
		s->size = i;
		return emu_memory_read_block(m, addr, s->data, i);
	}

}


int32_t emu_memory_write_byte(struct emu_memory *m, uint32_t addr, uint8_t byte)
{
	if ( m->read_only_access == true )
		return 0;
	

	addr += m->segment_offset;

	mm_check(addr,1,'w'); 

	/*
	if(addr==0){
		printf("Someone is trying to writebyte mem 0?\n");
		asm __volatile__ (".byte 0xCC"); 
	}*/

	if( addr < 0x1000 ) //there are some memory sections that should not support writes...dzzie
	{
		emu_errno_set(m->emu, EFAULT);
		emu_strerror_set(m->emu, "error accessing 0x%08x not mapped\n", addr);
		return -1;
	}

	void *address = translate_addr(m, addr);
	
	if( address == NULL )
	{
		if( page_alloc(m, addr) == -1 )
			return -1;

		address = translate_addr(m, addr);
	}
	
	*((uint8_t *)address) = byte;
	
	return 0;
}

int32_t emu_memory_write_word(struct emu_memory *m, uint32_t addr, uint16_t word)
{
	if (m->read_only_access == true)
		return 0;

#if BYTE_ORDER == BIG_ENDIAN
	uint16_t val;
	bcopy(&word, &val, 2);
	val = ((val & 0xff00) >> 8) | 
		  ((val & 0x00ff) << 8);
	return emu_memory_write_block(m, addr, &val, 2);
#else
	return emu_memory_write_block(m, addr, &word, 2);
#endif
}

int32_t emu_memory_write_dword(struct emu_memory *m, uint32_t addr, uint32_t dword)
{
	if (m->read_only_access == true)
		return 0;

#if BYTE_ORDER == BIG_ENDIAN
	uint32_t val;
	bcopy(&dword, &val, 4);
	val = ((val & (0xff000000)) >> 24) |
		  ((val & (0x00ff0000)) >> 8)  |
		  ((val & (0x0000ff00)) << 8)  |
		  ((val & (0x000000ff)) << 24);
	return emu_memory_write_block(m, addr, &val, 4);
#else
	return emu_memory_write_block(m, addr, &dword, 4);
#endif
}

int32_t emu_memory_write_block(struct emu_memory *m, uint32_t addr, void *src, size_t len)
{
	if (m->read_only_access == true)
		return 0;

	uint32_t oaddr = addr; /* save original addr for recursive call */
	addr += m->segment_offset;

	mm_check(addr,len,'w');

	/*if(addr==0){ //it was an opcode writing 0 that created memory at 0..
		printf("Someone is trying to writeblock mem 0?\n");
		asm __volatile__ (".byte 0xCC"); 
	}*/

	if( addr < 0x1000 ) //there are some memory sections that should not support writes...dzzie
	{                   //this is still overly permissive..should we require allocs? to much to change..
		emu_errno_set(m->emu, EFAULT);
		emu_strerror_set(m->emu, "error accessing 0x%08x not mapped\n", addr);
		return -1;
	}

	void *address = translate_addr(m, addr);

	if( address == NULL )
	{
		if( page_alloc(m, addr) == -1 )
			return -1;

		address = translate_addr(m, addr);
	}

	if (OFFSET(addr) + len <= PAGE_SIZE)
	{
		bcopy(src, address, len);
		return 0;
	}
	else
	{
		uint32_t cb = PAGE_SIZE - OFFSET(addr);
		bcopy(src, address, cb);
		return emu_memory_write_block(m, oaddr + cb, src + cb, len - cb);
	}

	return 0;

}

void emu_memory_segment_select(struct emu_memory *m, enum emu_segment s)
{
	m->segment_current = s;
	m->segment_offset = m->segment_table[m->segment_current];
}

enum emu_segment emu_memory_segment_get(struct emu_memory *m)
{
	return m->segment_current;
}

/* make sure a memory block of size *len* is allocated at *addr* */
/*int32_t emu_memory_alloc_at(struct emu_memory *m, uint32_t addr, size_t len)
{
	len += addr % PAGE_SIZE;
	addr = (addr >> PAGE_BITS) << PAGE_BITS;
	
	while( len > 0 )
	{
		if( len > PAGE_SIZE )
		{
			len -= PAGE_SIZE;
			page_alloc(m, addr);
			addr += PAGE_SIZE;
		}
		else
		{
			len -= len; 
			page_alloc(m, addr);
		}
	}

	return 0;
}*/

int32_t emu_memory_alloc(struct emu_memory *m, uint32_t *addr, size_t len)
{
	*addr = 0x00200000;
	
	uint32_t pages = len / PAGE_SIZE;
	
	if( len % PAGE_SIZE != 0 )
	{
		pages++;
	}

	int i;
	
	/* TODO: ensure termination */
	for( ; ; )
	{
		for( i = 0; i < pages; i++ )
		{
			if( page_is_alloc(m, *addr + i * PAGE_SIZE) != 0 )
			{
				break;
			}
		}
		
		if( i == pages )
		{
			for( i = 0; i < pages; i++ )
			{
				if( page_alloc(m, *addr + i * PAGE_SIZE) )
				{
					return -1;
				}
			}
			
			return 0;
		}
		
		*addr += len + PAGE_SIZE;
	}
	
	return -1;
}

void emu_memory_mode_ro(struct emu_memory *m)
{
	m->read_only_access = true;
}

void emu_memory_mode_rw(struct emu_memory *m)
{
	m->read_only_access = false;
}

void emu_memory_set_access_monitor(uint32_t lpfnCallback){
	mem_monitor_callback = (mm_callback)lpfnCallback;
}

void emu_memory_add_monitor_point(uint32_t address){
	if(mm_point_cnt == 255){
		printf("All available monitor points full...\n");
		return;
	}
	mm_points[mm_point_cnt++] = address;
}

void emu_memory_set_range_access_monitor(uint32_t lpfnCallback){
	mem_monitor_range_callback = (mm_range_callback)lpfnCallback;
}

void emu_memory_add_monitor_range(char id, uint32_t start_at, uint32_t end_at){
	
	if(mm_range_cnt == 255){
		printf("All available monitor ranges full...\n");
		return;
	}
	mm_ranges[mm_range_cnt].id       = id;
	mm_ranges[mm_range_cnt].start_at = start_at;
	mm_ranges[mm_range_cnt].end_at   = end_at;
	mm_range_cnt++;
	
}

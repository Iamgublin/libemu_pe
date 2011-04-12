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

#ifndef HAVE_EMU_H
#define HAVE_EMU_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef MIN
	#define        MIN(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef MAX
	#define        MAX(a,b) (((a)>(b))?(a):(b))
#endif

#include <memory.h>

#pragma warning( disable : 4996 ) //unsafe function (strcpy,vsnprintf)
#pragma warning( disable : 4018 ) //signed unsigned mismatch

struct emu;
struct emu_logging;
struct emu_cpu;
struct emu_fpu;

struct emu *emu_new(void);
void emu_free(struct emu *e);
struct emu_memory *emu_memory_get(struct emu *e);

struct emu_logging *emu_logging_get(struct emu *e);
struct emu_cpu *emu_cpu_get(struct emu *e);

void emu_errno_set(struct emu *e, int err);
int emu_errno(struct emu *c);
void emu_strerror_set(struct emu *e, const char *format, ...);
const char *emu_strerror(struct emu *e);

/*int32_t emu_parse(struct emu *e);
int32_t emu_step(struct emu *e);*/
#endif // HAVE_EMU_H

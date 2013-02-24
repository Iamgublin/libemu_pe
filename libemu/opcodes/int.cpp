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

#include "emu_cpu.h"
#include "emu_cpu_data.h"
#include "emu_memory.h"
#include "emu_string.h"

typedef int (*syscall_callback)(int callNumber,struct emu_cpu *c);
extern syscall_callback SYSCALL_callback;

int32_t instr_int_cd(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	uint8_t interrupt = *i->imm8;

	if( (int)SYSCALL_callback != 0 && interrupt == 0x2e){
		return SYSCALL_callback(0x2e,c); //needs to return -1 for fail or 0 for ok..
	}
	
	if( *i->imm8 == 0x80 ) emu_strerror_set(c->emu, "Linux Shellcode Unsupported: Called Int 0x%x\n", *i->imm8);
	  else emu_strerror_set(c->emu, "Unsupported instruction Interrupt 0x%x\n", *i->imm8);

	return -1;
}



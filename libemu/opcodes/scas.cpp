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

#include <stdint.h>
#include <errno.h>

#define INSTR_CALC(bits, a, b) \
UINTOF(bits) operation_result = (a) - (b); \
UINTOF(bits) operand_a = a; \
UINTOF(bits) operand_b = b;


#include "emu.h"
#include "emu_cpu.h"
#include "emu_cpu_data.h"

#include "emu_cpu_stack.h"
#include "emu_memory.h"

/*Intel Architecture Software Developer's Manual Volume 2: Instruction Set Reference (24319102.PDF) page 669

http://courses.engr.illinois.edu/ece390/archive/spr2002/books/labmanual/inst-ref-scasb.html

B.141 SCASB, SCASW, SCASD: Scan String

    SCASB                         ; AE                   [8086]
    SCASW                         ; o16 AF               [8086]
    SCASD                         ; o32 AF               [386]

	SCASB compares the byte in AL with the byte at [ES:DI] or [ES:EDI], and sets the flags accordingly. 
	It then increments or decrements (depending on the direction flag: increments if the flag is clear, 
	decrements if it is set) DI (or EDI).

	The register used is DI if the address size is 16 bits, and EDI if it is 32 bits. If you need to use
	an address size not equal to the current BITS setting, you can use an explicit a16 or a32 prefix.

	Segment override prefixes have no effect for this instruction: the use of ES for the load from [DI] 
	or [EDI] cannot be overridden.

	SCASW and SCASD work in the same way, but they compare a word to AX or a doubleword to EAX instead of 
	a byte to AL, and increment or decrement the addressing registers by 2 or 4 instead of 1.

	The REPE and REPNE prefixes (equivalently, REPZ and REPNZ) may be used to repeat the instruction up 
	to CX (or ECX - again, the address size chooses which) times until the first unequal or equal byte 
	is found.

*/

#define INSTR_CALC_AND_SET_FLAGS(bits, cpu, a, b) \
INSTR_CALC(bits, a, b) \
INSTR_SET_FLAG_ZF(cpu) \
INSTR_SET_FLAG_PF(cpu) \
INSTR_SET_FLAG_SF(cpu) \
INSTR_SET_FLAG_CF(cpu, -) \
INSTR_SET_FLAG_OF(cpu, -,bits) 


#define INSTR_CALC_EDI(cpu, bits) \
{ \
	if ( !CPU_FLAG_ISSET(cpu,f_df) ) \
	cpu->reg[edi]+=bits/8; \
else \
	cpu->reg[edi]-=bits/8; \
}

//repxx support added 5.17.11 dz 
int32_t instr_scas_ae(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	if ( i->prefixes & PREFIX_ADSIZE )
	{
		/* AE 
		 * Compare AL with byte at ES:DI and set status flags
		 * SCAS m8  
		 * Compare AL with byte at ES:DI and set status flags
		 * SCASB    
		 */
		UNIMPLEMENTED(c, SST);
		return 0;
	}
	 
	// SCASB (8bit)

	if ( i->prefixes & PREFIX_F2 || i->prefixes & PREFIX_F3){			
		c->repeat_current_instr = true;
	}

	enum emu_segment oldseg = emu_memory_segment_get(c->mem);
	emu_memory_segment_select(c->mem,s_es);

	uint8_t m8;
	uint8_t match = *c->reg8[al];

	MEM_BYTE_READ(c, c->reg[edi], &m8);
	emu_memory_segment_select(c->mem,oldseg);
	INSTR_CALC_AND_SET_FLAGS(8, c, *c->reg8[al], m8)
	INSTR_CALC_EDI(c, 8)
	 
	if ( i->prefixes & PREFIX_F2 || i->prefixes & PREFIX_F3) 
	{
		c->reg[ecx]--;
		if( c->reg[ecx] == 0 ){
			c->repeat_current_instr = false;
		}
		else{
			if( i->prefixes & PREFIX_F2){
				if(m8 == match ) c->repeat_current_instr = false;
			}

			if( i->prefixes & PREFIX_F3){
				if(m8 != match ) c->repeat_current_instr = false;
			}
		}

	}

	return 0;
}

// repxx support added 5.22.14 dz
int32_t instr_scas_af(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	if ( i->prefixes & PREFIX_ADSIZE )
	{
		if ( i->prefixes & PREFIX_OPSIZE )
		{
			/* AF 
			 * Compare AX with word at ES:DI and set status flags
			 * SCAS m16 
			 * Compare AX with word at ES:DI and set status flags
			 * SCASW    
			 */
			UNIMPLEMENTED(c, SST);
		}
		else
		{
			/* AF 
			 * Compare EAX with doubleword at ES:DI and set status flags
			 * SCAS m32 
			 * Compare EAX with doubleword at ES:DI and set status flags
			 * SCASD    
			 */
			UNIMPLEMENTED(c, SST);
		}


	}else
	{

		if ( i->prefixes & PREFIX_F2 || i->prefixes & PREFIX_F3){			
			c->repeat_current_instr = true;
		}

		if ( i->prefixes & PREFIX_OPSIZE )
		{
			// SCASW (16bit)
			enum emu_segment oldseg = emu_memory_segment_get(c->mem);
			emu_memory_segment_select(c->mem,s_es);

			uint16_t m16;
			uint16_t match = *c->reg16[ax];

			MEM_WORD_READ(c, c->reg[edi], &m16);
			emu_memory_segment_select(c->mem,oldseg);
			INSTR_CALC_AND_SET_FLAGS(16, c, *c->reg16[ax], m16)
			INSTR_CALC_EDI(c, 16)

			if ( i->prefixes & PREFIX_F2 || i->prefixes & PREFIX_F3) 
			{
				c->reg[ecx]--;
				if( c->reg[ecx] == 0 ){
					c->repeat_current_instr = false;
				}
				else{
					if( i->prefixes & PREFIX_F2){
						if(m16 == match ) c->repeat_current_instr = false;
					}

					if( i->prefixes & PREFIX_F3){
						if(m16 != match ) c->repeat_current_instr = false;
					}
				}

			}

		}
		else
		{
			// SCASD (32bit)
			enum emu_segment oldseg = emu_memory_segment_get(c->mem);
			emu_memory_segment_select(c->mem,s_es);

			uint32_t m32;
			uint32_t match = c->reg[eax];

			MEM_DWORD_READ(c, c->reg[edi], &m32);
			emu_memory_segment_select(c->mem,oldseg);
			INSTR_CALC_AND_SET_FLAGS(32, c, c->reg[eax], m32)
			INSTR_CALC_EDI(c, 32)

			if ( i->prefixes & PREFIX_F2 || i->prefixes & PREFIX_F3) 
			{
				c->reg[ecx]--;
				if( c->reg[ecx] == 0 ){
					c->repeat_current_instr = false;
				}
				else{
					if( i->prefixes & PREFIX_F2){
						if(m32 == match ) c->repeat_current_instr = false;
					}

					if( i->prefixes & PREFIX_F3){
						if(m32 != match ) c->repeat_current_instr = false;
					}
				}

			}
		}
	}
	return 0;
}

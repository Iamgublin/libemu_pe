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

#include "emu_cpu.h"
#include "emu_cpu_data.h"
#include "emu_cpu_stack.h"
#include "emu_memory.h"
#include "emu_log.h"
#include <errno.h>

int32_t prefix_repef3_alerter(struct emu_cpu *c, struct emu_cpu_instruction *i){

	switch(i->opc){
		case 0xAE: //scasb (ae)
		case 0xa6: //instr_cmps_a6
		case 0xA4: //instr_movsb (a4)
		case 0xA5: //instr_movs_a5 (a5 movsd/movsw)
		case 0xab: //instr_stos_ab
		case 0xAA: break; //instr_stos_aa
		
		default:
			emu_strerror_set(c->emu,"support for repe not implemented for opcode %X\n", i->opc);
			emu_errno_set(c->emu, EOPNOTSUPP);
			return -1;
	}

	return 0;
}

int32_t prefix_repnef2_alerter(struct emu_cpu *c, struct emu_cpu_instruction *i)
{

	switch(i->opc){
		case 0xA4: //instr_movsb (a4)		
		case 0xab: //instr_stos_ab
		case 0xae: break; //scasb 0xAe
		case 0xAA: break; //stoss_aa
		

		default:
			emu_strerror_set(c->emu,"support for repne not implemented for opcode %X\n", i->opc);
			emu_errno_set(c->emu, EOPNOTSUPP);
			return -1;
	}

	return 0;

}

int32_t implemented_prefix_check(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	/* dz 5.17.11 - only checks repxx for implementation so far */
    /*  REPxx operates on: MOVS/STOS/CMPS/LODS/SCAS */
    //http://pdos.csail.mit.edu/6.828/2006/readings/i386/REP.htm

	if( i->prefixes & PREFIX_F3) return prefix_repef3_alerter(c,i);
	if( i->prefixes & PREFIX_F2) return prefix_repnef2_alerter(c,i);

	return 0;
}

int32_t prefix_fn(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	/* dummy - never called */
	return 0;
}

//dzzie
int32_t instr_salc_d6(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	 
	/* d6 
		SALC stands for SET the Carry flag in AL
		sets AL=FF if the Carry Flag is set (CF=1), 
		or resets AL=00 if the Carry Flag is clear (CF=0).  
	 */   
	   
	*c->reg8[al] = CPU_FLAG_ISSET(c,f_cf) ? 0xFF : 0x00 ;

	return 0;
}

//dzzie
uint32_t last_TSC_EAX = 0;
uint32_t last_TSC_EDX = 0;
int32_t instr_rdtsc_0f31(struct emu_cpu *c, struct emu_cpu_instruction *i){
	/*The Time Stamp Counter is a 64-bit register present on all x86 
	processors since the Pentium that counts the number of ticks since reset. 
	returns the TSC in EDX:EAX*/
	if(last_TSC_EDX==0){
		_asm{
			rdtsc
			mov last_TSC_EDX, edx
			mov last_TSC_EAX, eax
		}
	}else{
		last_TSC_EAX += 0x100;
	}
	c->reg[edx]= last_TSC_EDX;
	c->reg[eax]= last_TSC_EAX;
	return 0;
}

int32_t instr_daa_27(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	/* 27
	 * Decimal Adjust AL after Addition
	 * DAA
	 */
	/*Intel Architecture Software Developer's Manual Volume 2: Instruction Set Reference (24319102.PDF) page 183*/
	//STUB(c);
	return 0;
}


int32_t instr_das_2f(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	/* F2
	 * Decimal Adjust AL after Subtraction
	 * DAS
	 */
	/*Intel Architecture Software Developer's Manual Volume 2: Instruction Set Reference (24319102.PDF) page 185*/
	//STUB(c);
	return 0;
}

int32_t instr_aas_3f(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	/* 3F
	 * ASCII Adjust AL After Subtraction
	 * aas
	 */
	/*Intel Architecture Software Developer's Manual Volume 2: Instruction Set Reference (24319102.PDF) page 60*/
	//STUB(c);
	return 0;
}




int32_t instr_wait_9b(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	/* 9B
	 * Wait
	 * wait
	 */
	/*Intel Architecture Software Developer's Manual Volume 2: Instruction Set Reference (24319102.PDF) page 747*/
	//STUB(c);
	return 0;
}

int32_t instr_pushf_9c(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	/* 9C
	 * Push EFLAGS Register onto the Stack
	 * pushf
	 */
	/*Intel Architecture Software Developer's Manual Volume 2: Instruction Set Reference (24319102.PDF) page 627*/

        PUSH_DWORD(c, c->eflags);
//	//STUB(c);
	return 0;
}

int32_t instr_popf_9d(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	/* 9D
	 * Pop Stack into EFLAGS Register
	 * popf
	 */
	/*Intel Architecture Software Developer's Manual Volume 2: Instruction Set Reference (24319102.PDF) page 578*/
        POP_DWORD(c, &c->eflags);
//	//STUB(c);
	return 0;
}

int32_t instr_sahf_9e(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	/* 9E
	 * Store AH into Flags
	 * SAHF
	 */
	/*Intel Architecture Software Developer's Manual Volume 2: Instruction Set Reference (24319102.PDF) page 661*/
	//STUB(c);
	return 0;
}

int32_t instr_lahf_9f(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	/* 9F
	 * Load Status Flags into AH Register
	 * SAHF
	 */
	/*Intel Architecture Software Developer's Manual Volume 2: Instruction Set Reference (24319102.PDF) page 381*/
	//STUB(c);
	return 0;
}


int32_t instr_cmc_f5(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	/* F5 
	 * Complement CF flag
	 * CMC 
	 */
	/*Intel Architecture Software Developer's Manual Volume 2: Instruction Set Reference (24319102.PDF) page 107*/
	CPU_FLAG_TOGGLE(c,f_cf);
	return 0;
}


int32_t instr_clc_f8(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	/* F8 
	 * Clear CF flag
	 * CLC 
	 */

	/*Intel Architecture Software Developer's Manual Volume 2: Instruction Set Reference (24319102.PDF) page 106*/
	CPU_FLAG_UNSET(c,f_cf);
	return 0;
}

int32_t instr_stc_f9(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	/* F9 
	 * Set CF flag
	 * STC 
	 */
	/*Intel Architecture Software Developer's Manual Volume 2: Instruction Set Reference (24319102.PDF) page 702*/
	CPU_FLAG_SET(c,f_cf);
	return 0;
}


int32_t instr_cld_fc(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	/*Intel Architecture Software Developer's Manual Volume 2: Instruction Set Reference (24319102.PDF) page 107*/
	CPU_FLAG_UNSET(c,f_df);
	return 0;
}

int32_t instr_std_fd(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	/*Intel Architecture Software Developer's Manual Volume 2: Instruction Set Reference (24319102.PDF) page 703*/
	/* FD 
	 * Set DF flag
	 * STD 
	 */
	CPU_FLAG_SET(c,f_df);
	return 0;
}






int32_t instr_lea_8d(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	/*Intel Architecture Software Developer's Manual Volume 2: Instruction Set Reference (24319102.PDF) page 393*/

	if ( i->prefixes & PREFIX_OPSIZE )
	{
		/* 8D /r 
		 * Store effective address for m in register r16
		 * LEA r16,m 
		 */
		UNIMPLEMENTED(c, SST);
	}
	else
	{
		/* 8D /r 
		 * Store effective address for m in register r32
		 * LEA r32,m 
		 */
		c->reg[i->modrm.opc] = i->modrm.ea;
		//TRACK_INIT_REG32(c->instr, i->modrm.opc);
	}
	return 0;

}


int32_t instr_cbw_98(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	/*Intel Architecture Software Developer's Manual Volume 2: Instruction Set Reference (24319102.PDF) page 104*/

	if ( i->prefixes & PREFIX_OPSIZE )
	{
		/* 98 
		 * AX <- sign-extend of AL
		 * CBW  
		 */
		*c->reg16[ax] = (int8_t)*c->reg8[al];
	}
	else
	{
    	/* 98 
		 * EAX <- sign-extend of AX
		 * CWDE 
		 */
		c->reg[eax] = (int16_t)*c->reg16[ax];
	}
	return 0;
}


int32_t instr_cwd_99(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	/*Intel Architecture Software Developer's Manual Volume 2: Instruction Set Reference (24319102.PDF) page 181*/

	if ( i->prefixes & PREFIX_OPSIZE )
	{
	   
		/* 99 
		 * DX:AX <- sign-extend of AX
		 * CWD 
		 */
		uint32_t sexd; 
		sexd = (int16_t)*c->reg16[ax];
		DWORD_UPPER_TO_WORD(*c->reg16[dx],sexd);
		DWORD_LOWER_TO_WORD(*c->reg16[ax],sexd);
		
	}
	else
	{
		/* 99 
		 * EDX:EAX <- sign-extend of EAX
		 * CDQ 
		 */
		uint64_t sexd; 
		sexd = (int32_t)c->reg[eax];
		QWORD_UPPER_TO_DWORD(c->reg[edx],sexd);
		QWORD_LOWER_TO_DWORD(c->reg[eax],sexd);

	}
	return 0;
}

int32_t instr_esc_fpu_dx(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	return 0;
}

int32_t instr_sldt_0f00(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
	/*Intel Architecture Software Developer's Manual Volume 2: Instruction Set Reference (24319102.PDF) page 692 */

	//STUB(c);

	if( i->prefixes & PREFIX_OPSIZE )
	{
		/* 0F 00 /0
		 * Stores segment selector from LDTR in r/m16
		 * SLDT r/m16
		 */

		if( i->modrm.mod != 3 )
		{
			uint16_t word = 0;
			MEM_WORD_WRITE(c, i->modrm.ea, word);
		}
		else
		{
			*c->reg16[i->modrm.rm] = 0;
		}
	}
	else
	{
		/* 0F 00 /0
		 * Store segment selector from LDTR in low-order 16 bits of r/m32
		 * SLDT r/m32
		 */

		if( i->modrm.mod != 3 )
		{
			uint32_t word = 0;
			MEM_DWORD_WRITE(c, i->modrm.ea, word);
		}
		else
		{
			c->reg[i->modrm.rm] = 0;
		}
	}
	return 0;
}

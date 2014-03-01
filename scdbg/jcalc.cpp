#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include "emu_cpu.h"
#include "emu_cpu_data.h"
#include "emu_memory.h"
#include "emu.h"
#include "emu_log.h"
#include "./../libemu/libdasm/libdasm.h"

#define OF_IS_ONE(cpu)  (CPU_FLAG_ISSET(cpu, f_of) != 0) 
#define OF_IS_ZERO(cpu) (CPU_FLAG_ISSET(cpu, f_of) == 0)
#define OF_IS(cpu)      (CPU_FLAG_ISSET(cpu, f_of)?1:0) 
 
#define CF_IS_ONE(cpu)  (CPU_FLAG_ISSET(cpu, f_cf) != 0) 
#define CF_IS_ZERO(cpu) (CPU_FLAG_ISSET(cpu, f_cf) == 0) 

#define ZF_IS_ONE(cpu)  (CPU_FLAG_ISSET(cpu, f_zf) != 0) 
#define ZF_IS_ZERO(cpu) (CPU_FLAG_ISSET(cpu, f_zf) == 0) 

#define SF_IS_ONE(cpu)  (CPU_FLAG_ISSET(cpu, f_sf) != 0) 
#define SF_IS_ZERO(cpu) (CPU_FLAG_ISSET(cpu, f_sf) == 0) 
#define SF_IS(cpu)      (CPU_FLAG_ISSET(cpu, f_sf)?1:0) 

#define PF_IS_ONE(cpu)  (CPU_FLAG_ISSET(cpu, f_pf) != 0) 
#define PF_IS_ZERO(cpu) (CPU_FLAG_ISSET(cpu, f_pf) == 0) 

int jcc_7x(struct emu_cpu *c, uint8_t id);
//int jcc_0f(struct emu_cpu *c, uint8_t id);

/*return values: 
	1 jump is taken
	0 jump is not taken
   -1 no memory at address
   -2 can not disasm address
   -3 jump type is not handled
   -4 eip is not a jmp or jxx instruction..invalid usage
*/
int isJumpTaken(struct emu_cpu *c, uint32_t eip){

	INSTRUCTION inst;
	uint8_t data[32];

	if(emu_memory_read_block(c->mem,eip,data,32) == -1) return -1; //no memory at address
    
	uint32_t instrsize = get_instruction(&inst, data, MODE_32);
	if( instrsize == 0 ) return -2; //can not disasm

	if(inst.type == INSTRUCTION_TYPE_JMP) return 1;

	if(inst.type == INSTRUCTION_TYPE_JMPC){
		uint8_t id = data[0];
		if( id == 0x0F ){         //near jump logic is the same except 
			 id = data[1] - 0x10; //offsets are 0x10 higher and has prefix byte
		}
		return jcc_7x(c, id);     //short jumps
	}

	return -4;
}


int jcc_7x(struct emu_cpu *c, uint8_t id){

	switch(id){
		case 0x70:
			/* 70 cb       Jump short if overflow (OF=1)                           JO rel8         */
			if (OF_IS_ONE(c)) return 1;
			break;

		case 0x71:
			/* 71 cb       Jump short if not overflow (OF=0)                       JNO rel8        */
			if (OF_IS_ZERO(c)) return 1;
			break;

		case 0x72:
			/* 72 cb       Jump short if below (CF=1)                              JB rel8         */
			/* 72 cb       Jump short if carry (CF=1)                              JC rel8         */
			/* 72 cb       Jump short if not above or equal (CF=1)                 JNAE rel8       */
			if (CF_IS_ONE(c)) return 1;
			break;

		case 0x73:
			/* 73 cb       Jump short if above or equal (CF=0)                     JAE rel8        */
			/* 73 cb       Jump short if not below (CF=0)                          JNB rel8        */
			/* 73 cb       Jump short if not carry (CF=0)                          JNC rel8        */
			if (CF_IS_ZERO(c)) return 1;
			break;

		case 0x74:
			/* 74 cb       Jump short if equal (ZF=1)                              JE rel8         */
			/* 74 cb       Jump short if zero (ZF = 1)                             JZ rel8         */
			if (ZF_IS_ONE(c)) return 1;
			break;

		case 0x75:
			/* 75 cb       Jump short if not equal (ZF=0)                          JNE rel8        */
			/* 75 cb       Jump short if not zero (ZF=0)                           JNZ rel8        */
			if (ZF_IS_ZERO(c)) return 1;
			break;

		case 0x76:
			/* 76 cb       Jump short if below or equal (CF=1 or ZF=1)             JBE rel8        */
			/* 76 cb       Jump short if not above (CF=1 or ZF=1)                  JNA rel8        */
			if (CF_IS_ONE(c) || ZF_IS_ONE(c)) return 1;
			break;

		case 0x77:
			/* 77 cb       Jump short if above (CF=0 and ZF=0)                     JA rel8         */
			/* 77 cb       Jump short if not below or equal (CF=0 and ZF=0)        JNBE rel8       */
			if (CF_IS_ZERO(c) && ZF_IS_ZERO(c)) return 1;
			break;

		case 0x78:
			/* 78 cb       Jump short if sign (SF=1)                               JS rel8         */
			if (SF_IS_ONE(c)) return 1;
			break;

		case 0x79:
			/* 79 cb       Jump short if not sign (SF=0)                           JNS rel8        */
			if (SF_IS_ZERO(c)) return 1;
			break;

		case 0x7a:
			/* 7A cb       Jump short if parity even (PF=1)                        JPE rel8        */
			/* 7A cb       Jump short if parity (PF=1)                             JP rel8         */
			if (PF_IS_ONE(c)) return 1;
			break;

		case 0x7b:
			/* 7B cb       Jump short if not parity (PF=0)                         JNP rel8        */
			/* 7B cb       Jump short if parity odd (PF=0)                         JPO rel8        */
			if (PF_IS_ZERO(c)) return 1;
			break;

		case 0x7c:
			/* 7C cb       Jump short if less (SF<>OF)                             JL rel8         */
			/* 7C cb       Jump short if not greater or equal (SF<>OF)             JNGE rel8       */
			if (SF_IS(c) != OF_IS(c)) return 1;
			break;

		case 0x7d:
			/* 7D cb       Jump short if greater or equal (SF=OF)                  JGE rel8        */
			/* 7D cb       Jump short if not less (SF=OF)                          JNL rel8        */
			if (SF_IS(c) == OF_IS(c)) return 1;
			break;

		case 0x7e:
			/* 7E cb       Jump short if less or equal (ZF=1 or SF<>OF)            JLE rel8        */
			/* 7E cb       Jump short if not greater (ZF=1 or SF<>OF)              JNG rel8        */
			if ( ZF_IS_ONE(c) || (SF_IS(c) != OF_IS(c))) return 1;
			break;

		case 0x7f:
			/* 7F cb       Jump short if greater (ZF=0 and SF=OF)                  JG rel8         */
			/* 7F cb       Jump short if not less or equal (ZF=0 and SF=OF)        JNLE rel8       */
			if ( ZF_IS_ZERO(c) && (SF_IS(c) == OF_IS(c))) return 1; //dzzie bugfix 8.2.12 (was ZF_IS_ONE)
			break;

		default:
			return -3; //not implemented
	}

	return 0; //was handled but didnt match

}

/* these are all the same except 0x10 greater in second byte..
int jcc_0f(struct emu_cpu *c, uint8_t id){

	switch(id){

		case 0x80:
			// 0F 80 cw/cd  Jump near if overflow (OF=1)                           JO rel16/32     
			if (OF_IS_ONE(c)) return 1;
			break;

		case 0x81:
			// 0F 81 cw/cd  Jump near if not overflow (OF=0)                       JNO rel16/32    
			if (OF_IS_ZERO(c)) return 1;
			break;

		case 0x82:
			// 0F 82 cw/cd  Jump near if below (CF=1)                              JB rel16/32     
			// 0F 82 cw/cd  Jump near if carry (CF=1)                              JC rel16/32     
			// 0F 82 cw/cd  Jump near if not above or equal (CF=1)                 JNAE rel16/32   
			if (CF_IS_ONE(c)) return 1;
			break;

		case 0x83:
			// 0F 83 cw/cd  Jump near if above or equal (CF=0)                     JAE rel16/32    
			// 0F 83 cw/cd  Jump near if not below (CF=0)                          JNB rel16/32    
			// 0F 83 cw/cd  Jump near if not carry (CF=0)                          JNC rel16/32    
			if (CF_IS_ZERO(c)) return 1;
			break;

		case 0x84:
			// 0F 84 cw/cd  Jump near if equal (ZF=1)                              JE rel16/32     
			// 0F 84 cw/cd  Jump near if zero (ZF=1)                               JZ rel16/32     
			if (ZF_IS_ONE(c)) return 1;
			break;

		case 0x85:
			// 0F 85 cw/cd  Jump near if not equal (ZF=0)                          JNE rel16/32    
			// 0F 85 cw/cd  Jump near if not zero (ZF=0)                           JNZ rel16/32    
			if (ZF_IS_ZERO(c)) return 1;
			break;

		case 0x86:
			// 0F 86 cw/cd  Jump near if below or equal (CF=1 or ZF=1)             JBE rel16/32    
			// 0F 86 cw/cd  Jump near if not above (CF=1 or ZF=1)                  JNA rel16/32    
			if (CF_IS_ONE(c) || ZF_IS_ONE(c)) return 1;
			break;

		case 0x87:
			// 0F 87 cw/cd  Jump near if above (CF=0 and ZF=0)                     JA rel16/32     
			// 0F 87 cw/cd  Jump near if not below or equal (CF=0 and ZF=0)        JNBE rel16/32   
			if (CF_IS_ZERO(c) && ZF_IS_ZERO(c)) return 1;
			break;

		case 0x88:
			// 0F 88 cw/cd  Jump near if sign (SF=1)                               JS rel16/32     
			if (SF_IS_ONE(c)) return 1;
			break;

		case 0x89:
			// 0F 89 cw/cd  Jump near if not sign (SF=0)                           JNS rel16/32    
			if (SF_IS_ZERO(c)) return 1;
			break;

		case 0x8A:
			// 0F 8A cw/cd  Jump near if parity even (PF=1)                        JPE rel16/32    
			// 0F 8A cw/cd  Jump near if parity (PF=1)                             JP rel16/32     
			if (PF_IS_ONE(c)) return 1;
			break;

		case 0x8B:
			// 0F 8B cw/cd  Jump near if not parity (PF=0)                         JNP rel16/32    
			// 0F 8B cw/cd  Jump near if parity odd (PF=0)                         JPO rel16/32    
			if (PF_IS_ZERO(c)) return 1;
			break;

		case 0x8C:
			// 0F 8C cw/cd  Jump near if less (SF<>OF)                             JL rel16/32     
			// 0F 8C cw/cd  Jump near if not greater or equal (SF<>OF)             JNGE rel16/32   
			if (SF_IS(c) != OF_IS(c)) return 1;
			break;

		case 0x8D:
			// 0F 8D cw/cd  Jump near if greater or equal (SF=OF)                  JGE rel16/32    
			// 0F 8D cw/cd  Jump near if not less (SF=OF)                          JNL rel16/32    
			if (SF_IS(c) == OF_IS(c)) return 1;
			break;

		case 0x8E:
			// 0F 8E cw/cd  Jump near if less or equal (ZF=1 or SF<>OF)            JLE rel16/32    
			// 0F 8E cw/cd  Jump near if not greater (ZF=1 or SF<>OF)              JNG rel16/32    
			if (ZF_IS_ONE(c) || SF_IS(c) != OF_IS(c)) return 1;
			break;

		case 0x8F:
			// 0F 8F cw/cd  Jump near if greater (ZF=0 and SF=OF)                  JG rel16/32     
			// 0F 8F cw/cd  Jump near if not less or equal (ZF=0 and SF=OF)        JNLE rel16/32   
			if (ZF_IS_ZERO(c) && SF_IS(c) == OF_IS(c)) return 1;
			break;

		default:
			return -3; //NOT IMPLEMENTED
	}

	return 0; //was handled but didnt match
}
*/

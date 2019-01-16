#include "emu_cpu.h"
#include "emu_cpu_data.h"

#include "emu_memory.h"

int32_t instr_xgetbv_0f01d0(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
    c->reg[emu_reg32::eax] = 0x7;
    c->reg[emu_reg32::edx] = 0;

    return 0;
}
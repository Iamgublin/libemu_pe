#include "emu_cpu.h"
#include "emu_cpu_data.h"

#include "emu_memory.h"

int32_t instr_cpuid_0fa2(struct emu_cpu *c, struct emu_cpu_instruction *i)
{
    int inputeax = c->reg[emu_reg32::eax];
    int inputebx = c->reg[emu_reg32::ebx];
    int inputecx = c->reg[emu_reg32::ecx];
    int inputedx = c->reg[emu_reg32::edx];

    int reax = c->reg[emu_reg32::eax];
    int rebx = c->reg[emu_reg32::ebx];
    int recx = c->reg[emu_reg32::ecx];
    int redx = c->reg[emu_reg32::edx];

    __asm
    {
        pushad;
        mov eax, reax;
        mov ebx, rebx;
        mov ecx, recx;
        mov edx, redx;
        cpuid;
        mov reax, eax;
        mov rebx, ebx;
        mov recx, ecx;
        mov redx, edx;
        popad;
    }

    c->reg[emu_reg32::eax] = reax;
    c->reg[emu_reg32::ebx] = rebx;
    c->reg[emu_reg32::ecx] = recx;
    c->reg[emu_reg32::edx] = redx;

    return 0;
}
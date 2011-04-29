using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;


namespace c_sharp
{
    static class test
    {

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct emu_cpu
        {
            public uint lpEmu;
            public uint lpMem;
            public uint repeat_current_instr;
            public uint debugFlags;
            public uint eip;
            public uint eflags;
            public uint eax;
            public uint ecx;
            public uint edx;
            public uint ebx;
            public uint esp;
            public uint ebp;
            public uint esi;
            public uint edi;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct emu_env_w32_dll_export
        {
            public uint lpfnName;
            public uint VirtualAddress;
            public uint lpfnHook;
            public uint userdata;
        }

        public delegate UInt32 ApiHookProc(UInt32 hEnv, UInt32 hHook);

        public enum emu_reg32{eax = 0,ecx,edx,ebx,esp,ebp,esi,edi}

        [DllImport("kernel32.dll", EntryPoint = "RtlMoveMemory")]
        static extern unsafe void CopyMemory(byte* Destination, uint Source, uint Length);

        [DllImport("KERNEL32.DLL")]
        public static extern int IsBadReadPtr(uint lpBase, uint ucb);  

        [DllImport("vslibemu.dll")]//struct emu_env_hook *emu_env_w32_eip_check(struct emu_env *env);
        private static unsafe extern
        emu_env_w32_dll_export* emu_env_w32_eip_check(UInt32 hEnv);
        
        [DllImport("vslibemu.dll")]//'uint32_t emu_disasm_addr(struct emu_cpu *c, uint32_t eip, char *str);
        private static unsafe extern 
        UInt32 emu_disasm_addr(emu_cpu* hCpu, UInt32 eip, StringBuilder buf99);

       [DllImport("vslibemu.dll")]//int32_t emu_cpu_run(struct emu_cpu *c);
        private static unsafe extern 
        UInt32 emu_cpu_run(emu_cpu* hCpu);

       [DllImport("vslibemu.dll")]//uint32_t emu_cpu_eip_get(struct emu_cpu *c);
        private static unsafe extern 
        UInt32 emu_cpu_eip_get(emu_cpu* hCpu);

       [DllImport("vslibemu.dll")]//int32_t emu_cpu_parse(struct emu_cpu *c);
        private static unsafe extern 
        Int32 emu_cpu_parse(emu_cpu* hCpu);

       [DllImport("vslibemu.dll")]//
        private static unsafe extern 
        Int32 emu_cpu_step(emu_cpu* hCpu);

       [DllImport("vslibemu.dll")]//
        private static unsafe extern 
        UInt32 emu_cpu_eip_set(emu_cpu* hCpu, UInt32 eip);

        [DllImport("vslibemu.dll")]//
        private static extern 
        UInt32 emu_new();

        [DllImport("vslibemu.dll")]//
        private static extern unsafe 
        emu_cpu* emu_cpu_get(UInt32 hEmu);

        [DllImport("vslibemu.dll")]//struct emu_memory *emu_memory_get(struct emu *e);
        private static extern 
        UInt32 emu_memory_get(UInt32 hEmu);


       [DllImport("vslibemu.dll")]//'struct emu_env *emu_env_new(struct emu *e);
        private static extern 
        UInt32 emu_env_new(UInt32 hEmu);

        [DllImport("vslibemu.dll")]//const char *emu_strerror(struct emu *e);
        private static extern 
        string emu_strerror(UInt32 hEmu);

        [DllImport("vslibemu.dll")]//uint32_t emu_cpu_reg32_get(struct emu_cpu *cpu_p, enum emu_reg32 reg);
        private static unsafe extern 
        UInt32 emu_cpu_reg32_get(emu_cpu* hCpu, emu_reg32 reg32);

        [DllImport("vslibemu.dll")]//'void emu_cpu_reg32_set(struct emu_cpu *cpu_p, enum emu_reg32 reg, uint32_t val);
        private static unsafe extern 
        UInt32 emu_cpu_reg32_set(emu_cpu* hCpu, emu_reg32 reg32, UInt32 val);

        [DllImport("vslibemu.dll")]//int32_t emu_memory_write_block(struct emu_memory *m, uint32_t addr, void *src, size_t len);
        private static extern unsafe 
         UInt32 emu_memory_write_block(UInt32 hMem, UInt32 addr, byte* src, UInt32 length);

        [DllImport("vslibemu.dll")]//int32_t emu_memory_read_block(struct emu_memory *m, uint32_t addr, void *dest, size_t len);
        private static extern unsafe
        UInt32 emu_memory_read_block(UInt32 hMem, UInt32 addr, byte* dest, UInt32 length);
    
       [DllImport("vslibemu.dll")]//int32_t emu_memory_read_byte(struct emu_memory *m, uint32_t addr, uint8_t *byte);
       private static extern unsafe
       UInt32 emu_memory_read_byte(UInt32 hMem, UInt32 addr, byte* b);

       [DllImport("vslibemu.dll")]//int32_t emu_memory_read_dword(struct emu_memory *m, uint32_t addr, uint32_t *dword);
       private static extern unsafe
       UInt32 emu_memory_read_dword(UInt32 hMem, UInt32 addr, uint* b);

      [DllImport("vslibemu.dll")]//int32_t emu_env_w32_export_new_hook(struct emu_env *env, const char *exportname, lpfnCallback, void* Userdata
      private static extern 
      UInt32 emu_env_w32_export_new_hook(UInt32 hEnv, string ExportName, ApiHookProc ah, UInt32 userData);
      
    private static unsafe UInt32 hook_LoadLibraryA(UInt32 hEnv, UInt32 hExport)
    {
        uint eip_save = POP_DWORD();
        uint p_dll = POP_DWORD();
        string dll = ReadString(p_dll, 256);
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("\nLoadLibrary("+dll+") return address = " + eip_save.ToString("X")+"\n");
        Console.ForegroundColor = ConsoleColor.Gray;
        cpu->eax = 0x7c80000; //emu_cpu_reg32_set(cpu, emu_reg32.eax, 0X7C80000);
        cpu->eip = eip_save; //emu_cpu_eip_set(cpu, eip_save); 
        return 0;
    }

    public static unsafe string ReadString(uint addr, uint maxLen){
        string s = System.String.Empty;
        byte b;
        for(int i=0;i<maxLen;i++){
            emu_memory_read_byte(mem, (uint)(addr+i), &b);
            if( b==0) break;
            s += (char)b;
        }
        return s.ToString(); 
    }

    public static unsafe uint POP_DWORD(){
        uint esp = cpu->esp;  // emu_cpu_reg32_get(cpu, emu_reg32.esp);
        uint rval = 0;
        emu_memory_read_dword(mem, esp, &rval);
        //emu_cpu_reg32_set(cpu, emu_reg32.esp, esp + 4);
        cpu->esp += 4;
        return rval;
    }
        
      public static unsafe void WriteShellcode(UInt32 addr, byte[] b){
          fixed (byte* bb = &b[0])
          {
              emu_memory_write_block(mem, addr, bb, (uint)b.Length);
          }
      }

      public static unsafe string CString(uint lpString, uint maxLen)
      {
          string s = System.String.Empty;
          byte[] b = new byte[maxLen];
          if (IsBadReadPtr(lpString, maxLen) != 0) return s;
          fixed (byte* bb = &b[0]){ CopyMemory(bb, lpString, maxLen); }
          for (int i = 0; i < maxLen; i++)
          {
              if (b[i] == 0) break;
              s += (char)b[i];
          }
          return s ;

      }
      public static unsafe void print_disasm()
      {
          uint eip = emu_cpu_eip_get(cpu);
          StringBuilder buf = new StringBuilder(500);
          uint sz = emu_disasm_addr(cpu, eip, buf);
          Console.WriteLine(eip.ToString("X") + "\t" + buf);
      }

      public static unsafe bool Step()
      {
          if (emu_cpu_parse(cpu) == -1) return false;
          if (emu_cpu_step(cpu) == -1) return false;
          return true;
      }

        public static UInt32 e;
        public static unsafe emu_cpu* cpu;
        public static UInt32 mem;
        public static UInt32 env;

      static unsafe void Main(string[] args)
        {
          
            e = emu_new();
            cpu = emu_cpu_get(e);
            mem = emu_memory_get(e);
            env = emu_env_new(e);

            Console.WriteLine("hEmu=" + e.ToString("X") + " hMem=" + mem.ToString("X") + " hEnv=" + env.ToString("X"));

            //emu_cpu_reg32_set( cpu, emu_reg32.esp  , 0x12FE00);
            //emu_cpu_reg32_set( cpu, emu_reg32.ebp, 0x12FFF0);

            cpu->esp = 0x12FE00;
            cpu->ebp = 0x12FFF0;

            //ApiHookProc ahp = new ApiHookProc(hook_LoadLibraryA);
            UInt32 r = emu_env_w32_export_new_hook(env, "LoadLibraryA", hook_LoadLibraryA, 0);
            Console.WriteLine("SetHook returned: " + r+"\n");
 
            //mov eax, 0; inc eax, int 3 
            //byte[] b = { 0xb8, 0x00, 0x00, 0x00, 0x00, 0x40, 0xcc, 0xcc };

            //00436A3D     68 6C333200    PUSH 32336C
		    //00436A42     68 7368656C    PUSH 6C656873
		    //00436A47     54             PUSH ESP
		    //00436A48     68 771D807C    PUSH 7C801D77  ;LoadLibrary address
		    //00436A4D     59             POP ECX
		    //00436A4E     FFD1           CALL ECX 
            //00436A48     68 A0AD807C    PUSH 7c80ada0 ;GetProcAddress (stack not setup properly though for legit call)
            //00436A4D     59             POP ECX
            //00436A4E     FFD1           CALL ECX

	        byte[] b = {0x68, 0x6C, 0x33, 0x32, 0x00, 0x68, 0x73, 0x68, 0x65, 0x6C, 0x54, 
                        0x68, 0x77, 0x1D, 0x80, 0x7C, 0x59, 0xFF, 0xD1,0x68, 0xa0, 0xad, 
                        0x80, 0x7c, 0x59, 0xFF, 0xD1, 0xCC };

            WriteShellcode(0x401000, b);

            //emu_cpu_eip_set(cpu, 0x401000);
            cpu->eip = 0x401000;

            Console.WriteLine("Eip = " + emu_cpu_eip_get(cpu));
 
            for (int i = 0; i < 100; i++)
            {
                emu_env_w32_dll_export* export = emu_env_w32_eip_check(env);
                if ( (int)export != 0)
                {
                    if (export->lpfnHook == 0){ //then it is an api start address, but its not hooked..
                        Console.WriteLine("\nUnhooked api: " + CString(export->lpfnName,256));
                        break;
                    }
                }
                else
                {
                    print_disasm();
                    if (!Step()) break;
                }
            }

            Console.WriteLine("\nError: " + emu_strerror(e));
            Console.WriteLine("Run Complete eax=" + emu_cpu_reg32_get(cpu, emu_reg32.eax).ToString("X") );  
            Console.ReadKey();
 
        }
    }
}

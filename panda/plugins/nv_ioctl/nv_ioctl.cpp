#include "panda/plugin.h"

using namespace std;

// These need to be extern "C" so that the ABI is compatible with QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
}

// Function offsets inside the nvidia kernel module
// $ readelf -s nvidia.ko
#define NVIDIA_IOCTL 0x38c0
#define NVIDIA_IOCTL_RET 0x395e
#define NVIDIA_MEMCPY_FROM_USER 0xd7c0

// Function offsets inside the nvidia-modeset kernel module
// $ readelf -s nvidia-modeset.ko
#define NVKMS_IOCTL 0xd70
#define NVKMS_COPYIN 0x4dc
#define NVKMS_COPYOUT 0x52a

panda_cb pcb;
uint64_t nvidia_addr;
uint64_t nvidia_modeset_addr;

char out_filename[40];
target_ulong data_addr;
int size;
int ioctl_count = 0;
int struct_count = 0;
target_ulong structs[10];
int struct_sizes[10];

void dump_data(CPUState *cpu, target_ulong address, int size) {
    char target[size];
    if (panda_virtual_memory_rw(cpu, address, (uint8_t *)&target, size, false)) {
        printf("read failed!\n");
        return;
    }
    FILE *fp = fopen(out_filename, "wb");
    fwrite(target, 1, size, fp);
    fclose(fp);
}

void before_block_exec(CPUState *cpu, TranslationBlock *tb) {
    if (tb->pc == nvidia_addr + NVIDIA_IOCTL || tb->pc == nvidia_modeset_addr + NVKMS_IOCTL) {
        struct_count = 0;
        data_addr = ((CPUArchState *)cpu->env_ptr)->regs[R_ECX];
        target_ulong edx = ((CPUArchState *)cpu->env_ptr)->regs[R_EDX];

        int cmd = edx & 0xff;
        int type = (edx >> 8) & 0xff;
        size = (edx >> 16) & 0xfff;

        printf("IOCTL: type: %x, cmd: %x, size: %x, data ptr: %lx\n", type, cmd, size, data_addr);

        ioctl_count++;
        sprintf(out_filename, "ioctl-%i", ioctl_count);
        dump_data(cpu, data_addr, size);
    } else if (tb->pc == nvidia_addr + NVIDIA_IOCTL_RET) {
        sprintf(out_filename, "ioctl-%i-ret", ioctl_count);
        dump_data(cpu, data_addr, size);

        for (int i = 0; i < struct_count; i++) {
            sprintf(out_filename, "ioctl-%i-ret-0x%lx", ioctl_count, structs[i]);
            dump_data(cpu, structs[i], struct_sizes[i]);
        }
    } else if (tb->pc == nvidia_addr + NVIDIA_MEMCPY_FROM_USER) {
        target_ulong from = ((CPUArchState *)cpu->env_ptr)->regs[R_ESI];
        target_ulong size = ((CPUArchState *)cpu->env_ptr)->regs[R_EDX];

        structs[struct_count] = from;
        struct_sizes[struct_count] = size;
        struct_count++;

        sprintf(out_filename, "ioctl-%i-0x%lx", ioctl_count, from);
        dump_data(cpu, from, size);
    } else if (tb->pc == nvidia_modeset_addr + NVKMS_COPYIN) {
        target_ulong esi = ((CPUArchState *)cpu->env_ptr)->regs[R_ESI];
        target_ulong edx = ((CPUArchState *)cpu->env_ptr)->regs[R_EDX];

        printf("COPYIN 0x%lx, size: 0x%lx\n", esi, edx);

        sprintf(out_filename, "ioctl-%i-0x%lx-in", ioctl_count, esi);
        dump_data(cpu, esi, edx);
    } else if (tb->pc == nvidia_modeset_addr + NVKMS_COPYOUT) {
        target_ulong esi = ((CPUArchState *)cpu->env_ptr)->regs[R_ESI];
        target_ulong edx = ((CPUArchState *)cpu->env_ptr)->regs[R_EDX];

        printf("COPYOUT 0x%lx, size: 0x%lx\n", esi, edx);

        sprintf(out_filename, "ioctl-%i-0x%lx-out", ioctl_count, esi);
        dump_data(cpu, esi, edx);
    }
}

bool init_plugin(void *self) {
    panda_arg_list *panda_args = panda_get_args("nv_ioctl");
    nvidia_addr = panda_parse_uint64_opt(panda_args, "nvidia", 0, "nvidia kernel module address");
    nvidia_modeset_addr = panda_parse_uint64_opt(panda_args, "nvidia-modeset", 0,
                                                 "nvidia-modeset kernel module address");

    // Track execution paths, hook functions like IOCTL and dump data
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    return true;
}

void uninit_plugin(void *self) {}

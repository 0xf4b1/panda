#include "panda/plugin.h"
#include <unordered_map>

using namespace std;

// These need to be extern "C" so that the ABI is compatible with QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
}

#define NV_DMA_MAP_PAGES 0x7ff0
#define NV_DMA_UNMAP_PAGES 0x83e0

typedef struct dma_page {
    hwaddr address;
    hwaddr size;
    uint32_t crc;
    void *ptr;
} dma_page;

typedef struct dma_log {
    uint64_t rr_guest_instr_count;
    hwaddr addr;
    hwaddr size;
} dma_log;

panda_cb pcb;
uint64_t addr;
bool replay = false;
bool replay_fast = false;
FILE *dma_record;
unordered_map<hwaddr, dma_page *> dma_pages;
dma_page *last_page_write;
dma_log *next_dma_log = NULL;

static inline uint32_t checksum(dma_page *page) {
    uint32_t crc = crc32(0, Z_NULL, 0);
    target_ulong offset = 0;
    size_t remaining = page->size;
    while (remaining > 0) {
        uint32_t sz = remaining >= UINT32_MAX ? UINT32_MAX : (uint32_t)remaining;
        crc = crc32(crc, (unsigned char *)page->ptr + offset, sz);
        remaining -= sz;
        offset += sz;
    }
    return crc;
}

dma_page *get_page(hwaddr addr) {
    std::unordered_map<hwaddr, dma_page *>::const_iterator got = dma_pages.find(addr & 0xFFFFF000);
    if (got == dma_pages.end())
        return NULL;
    else
        return got->second;
}

void read_dma_log(CPUState *cpu, target_ptr_t addr) {
    // no more DMA records
    if (next_dma_log == NULL)
        return;

    if (cpu->rr_guest_instr_count > next_dma_log->rr_guest_instr_count) {
        printf("icount missmatch!\n");
        exit(-1);
    }

    if ((addr & 0xFFFFF000) != next_dma_log->addr)
        return;

    if (!replay_fast) {
        dma_page *page = get_page(addr);
        if (page == NULL)
            return;
    }

    char buf[next_dma_log->size];
    if (!fread(&buf, next_dma_log->size, 1, dma_record)) {
        printf("Error reading DMA data\n");
        exit(-1);
    }

    if (panda_physical_memory_rw((addr & 0xFFFFF000), (uint8_t *)&buf, next_dma_log->size, 1))
        printf("DMA write failed!\n");

    if (!fread(next_dma_log, sizeof(dma_log), 1, dma_record)) {
        printf("No more DMA records.\n");
        free(next_dma_log);
        next_dma_log = NULL;
    }
}

void write_dma_log(CPUState *cpu, target_ptr_t addr) {
    dma_page *page = get_page(addr);
    if (page != NULL) {
        uint32_t crc = checksum(page);
        if (page->crc != crc) {
            fwrite(&cpu->rr_guest_instr_count, sizeof(uint64_t), 1, dma_record);
            fwrite(&page->address, sizeof(hwaddr), 1, dma_record);
            fwrite(&page->size, sizeof(hwaddr), 1, dma_record);
            fwrite(page->ptr, page->size, 1, dma_record);
            page->crc = crc;
        }
    }
}

void phys_mem_before_read(CPUState *env, target_ptr_t pc, target_ptr_t addr, size_t size) {
    if (!replay && rr_in_record())
        write_dma_log(env, addr);
    else if (replay && rr_in_replay())
        read_dma_log(env, addr);
}

void phys_mem_before_write(CPUState *env, target_ptr_t pc, target_ptr_t addr, size_t size,
                           uint8_t *buf) {
    if (!rr_in_record())
        return;

    dma_page *page = get_page(addr);

    if (page != NULL) {
        // check if page is already dirty
        if (page->crc == 0x0)
            return;

        // check if page was externally written and if so mark it as dirty page
        uint32_t crc = checksum(page);
        if (crc != page->crc)
            page->crc = 0x0;
        else
            last_page_write = page;
    }
}

void phys_mem_after_write(CPUState *env, target_ptr_t pc, target_ptr_t addr, size_t size,
                          uint8_t *buf) {
    if (last_page_write != NULL) {
        // if the page is not dirty, update the crc, so that this write will not cause a DMA record
        if (last_page_write->crc != 0x0)
            last_page_write->crc = checksum(last_page_write);

        last_page_write = NULL;
    }
}

void map_dma_page(CPUState *cpu, hwaddr addr, int page_size, int count) {
    hwaddr len = page_size;

    rcu_read_lock();
    void *ptr = qemu_map_ram_ptr(NULL, addr);
    rcu_read_unlock();

    dma_page *page = (dma_page *)malloc(sizeof(dma_page));
    page->address = addr;
    page->size = len;
    page->ptr = ptr;
    page->crc = checksum(page);

    dma_pages.emplace(addr, page);
}

void before_block_exec(CPUState *cpu, TranslationBlock *tb) {
    // Logging of DMA page mappings in the nvidia kernel interface
    if (tb->pc == addr + NV_DMA_MAP_PAGES) {
        // page_count -> RSI
        // va_array -> RDX (contains page_count pages)
        // contig -> RCX
        // priv -> RBX
        // nv_state -> RDI

        target_ulong esi = ((CPUArchState *)cpu->env_ptr)->regs[R_ESI];
        target_ulong edx = ((CPUArchState *)cpu->env_ptr)->regs[R_EDX];
        target_ulong ecx = ((CPUArchState *)cpu->env_ptr)->regs[R_ECX];

        printf("pc: %lx, NV_DMA_MAP_PAGES: va_array: %lx, page_count: %lx, contig: %lx\n", tb->pc,
               edx, esi, ecx);

        int count;
        int page_size;

        if (ecx) {
            count = 1;
            page_size = 0x1000 * esi;
        } else {
            count = esi;
            page_size = 0x1000;
        }

        target_ulong target[count];
        if (panda_virtual_memory_rw(cpu, edx, (uint8_t *)&target, count * sizeof(target_ulong),
                                    false)) {
            printf("failed to get page addresses\n");
            return;
        }

        // map all pages
        for (int i = 0; i < count; i++) {
            // check if page is mapped already
            if (get_page(target[i]))
                return;

            map_dma_page(cpu, target[i], page_size, count);
        }
    } else if (tb->pc == addr + NV_DMA_UNMAP_PAGES) {
        // NV_DMA_UNMAP_PAGES
        // page_count -> RSI
        // va_array -> RDX (contains page_count pages)
        // priv -> RCX
        // nv_state -> RDI

        target_ulong esi = ((CPUArchState *)cpu->env_ptr)->regs[R_ESI];
        target_ulong edx = ((CPUArchState *)cpu->env_ptr)->regs[R_EDX];

        printf("pc: %lx, NV_DMA_UNMAP_PAGES: va_array: %lx, page_count: %lx\n", tb->pc, edx, esi);

        int count;
        target_ulong target[esi];
        if (panda_virtual_memory_rw(cpu, edx, (uint8_t *)&target, sizeof(target_ulong), false)) {
            printf("failed to get page addresses\n");
            return;
        }

        dma_page *page = get_page(target[0]);

        // contig page
        if (page->size > 0x1000) {
            count = 1;
        } else {
            count = esi;
            panda_virtual_memory_rw(cpu, edx, (uint8_t *)&target, count * sizeof(target_ulong),
                                    false);
        }

        for (int i = 0; i < count; i++) {
            if (get_page(target[i]))
                dma_pages.erase(target[i]);
        }
    }
}

void before_block_exec_replay_fast(CPUState *cpu, TranslationBlock *tb) {
    if (next_dma_log && next_dma_log->rr_guest_instr_count < cpu->rr_guest_instr_count + tb->icount)
        read_dma_log(cpu, next_dma_log->addr);
}

bool init_plugin(void *self) {
    panda_arg_list *panda_args = panda_get_args("nv_dma");
    addr = panda_parse_uint64_opt(panda_args, "addr", 0, "kernel module address");
    replay = panda_parse_bool(panda_args, "replay");
    replay_fast = panda_parse_bool(panda_args, "replay_fast");

    if (replay_fast) {
        // replay based on icount and page addresses
        pcb.before_block_exec = before_block_exec_replay_fast;
        panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    } else {
        panda_enable_precise_pc();

        // Enable memory logging
        panda_enable_memcb();

        // DMA
        pcb.before_block_exec = before_block_exec;
        panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

        pcb.phys_mem_before_read = phys_mem_before_read;
        panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_READ, pcb);

        if (!replay) {
            // Function hooks for DMA mappings during record
            pcb.phys_mem_before_write = phys_mem_before_write;
            panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_WRITE, pcb);

            pcb.phys_mem_after_write = phys_mem_after_write;
            panda_register_callback(self, PANDA_CB_PHYS_MEM_AFTER_WRITE, pcb);
        }
    }

    if (replay || replay_fast) {
        // Open DMA record and read first entry
        dma_record = fopen("dma_record.log", "rb");
        if (!dma_record) {
            printf("DMA record missing\n");
            return false;
        }
        next_dma_log = (dma_log *)malloc(sizeof(dma_log));
        if (!fread(next_dma_log, sizeof(dma_log), 1, dma_record)) {
            printf("DMA log is empty!\n");
            return false;
        }
    } else {
        // Open file for DMA record writing
        dma_record = fopen("dma_record.log", "wb");
    }

    return true;
}

void uninit_plugin(void *self) { fclose(dma_record); }

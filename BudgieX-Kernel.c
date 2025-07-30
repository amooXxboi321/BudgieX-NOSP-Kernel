// =========================
// BudgieX Kernel - The NOSP
// =========================
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
 #include <string.h>

// =========================
// Architecture Detection
// =========================
#ifdef __x86_64__
  #define ARCH_X86_64
#else
  #define ARCH_X86_32
#endif

// =========================
// Forward declaration
// =========================
void kernel_main(void* core_squashfs_addr);

// =========================
// Low-level I/O ports
// =========================
static inline void outb(uint16_t port, uint8_t val) {
    asm volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t val;
    asm volatile("inb %1, %0" : "=a"(val) : "Nd"(port));
    return val;
}

// =========================
// Serial Port Debug Output
// =========================
#define SERIAL_PORT 0x3F8

int memcmp(const void* s1, const void* s2, size_t n) {
    const uint8_t* a = (const uint8_t*)s1;
    const uint8_t* b = (const uint8_t*)s2;
    while (n--) { if (*a != *b) return *a - *b; a++; b++; }
    return 0;
}
int strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}
void* memmove(void* dest, const void* src, size_t n) {
    uint8_t* d = (uint8_t*)dest;
    const uint8_t* s = (const uint8_t*)src;
    if (d < s) { while (n--) *d++ = *s++; }
    else { d += n; s += n; while (n--) *(--d) = *(--s); }
    return dest;
}
void* k_memchr(const void* s, int c, size_t n) {
    const uint8_t* p = (const uint8_t*)s;
    while (n--) { if (*p == (uint8_t)c) return (void*)p; p++; }
    return NULL;
}
void memswap(void* a, void* b, size_t n) {
    uint8_t* p = (uint8_t*)a;
    uint8_t* q = (uint8_t*)b;
    while (n--) { uint8_t tmp = *p; *p++ = *q; *q++ = tmp; }
}
void memreverse(void* s, size_t n) {
    uint8_t* p = (uint8_t*)s;
    size_t i = 0, j = n-1;
    while (i < j) { uint8_t tmp = p[i]; p[i++] = p[j]; p[j--] = tmp; }
}
void memzero_secure(void* s, size_t n) {
    volatile uint8_t* p = (volatile uint8_t*)s;
    while (n--) *p++ = 0;
}

// =========================
// Heap allocator
// =========================
#define HEAP_SIZE (1024*1024)
static uint8_t heap[HEAP_SIZE];
typedef struct BlockHeader {
    size_t size;
    int free;
    struct BlockHeader *next;
    struct BlockHeader *prev;
} BlockHeader;
static BlockHeader *free_list;
static BlockHeader *next_fit;

static inline size_t align(size_t sz) { return (sz + 7) & ~7; }
void heap_init() {
    free_list = (BlockHeader*)heap;
    free_list->size = HEAP_SIZE - sizeof(BlockHeader);
    free_list->free = 1;
    free_list->next = NULL;
    free_list->prev = NULL;
    next_fit = free_list;
}
static BlockHeader* split_block(BlockHeader *block, size_t size) {
    if (block->size <= size + sizeof(BlockHeader)) return block;
    BlockHeader *new_block = (BlockHeader*)((uint8_t*)block + sizeof(BlockHeader) + size);
    new_block->size = block->size - size - sizeof(BlockHeader);
    new_block->free = 1;
    new_block->next = block->next;
    new_block->prev = block;
    if (block->next) block->next->prev = new_block;
    block->next = new_block;
    block->size = size;
    return block;
}
static BlockHeader* find_best_fit(size_t size) {
    BlockHeader *best = NULL;
    for (BlockHeader *cur = free_list; cur; cur = cur->next) {
        if (cur->free && cur->size >= size) {
            if (!best || cur->size < best->size) best = cur;
        }
    }
    return best;
}
static void coalesce(BlockHeader *block) {
    if (block->next && block->next->free) {
        block->size += sizeof(BlockHeader) + block->next->size;
        block->next = block->next->next;
        if (block->next) block->next->prev = block;
    }
}
void* kmalloc(size_t size) {
    size = align(size);
    BlockHeader *block = find_best_fit(size);
    if (!block) return NULL;
    block = split_block(block, size);
    block->free = 0;
    next_fit = block->next ? block->next : free_list;
    return (uint8_t*)block + sizeof(BlockHeader);
}
void kfree(void *ptr) {
    if (!ptr) return;
    BlockHeader *block = (BlockHeader*)((uint8_t*)ptr - sizeof(BlockHeader));
    block->free = 1;
    coalesce(block);
    if (block->prev && block->prev->free) {
        block = block->prev;
        coalesce(block);
    }
    next_fit = block;
}

// =========================
// Paging
// =========================
#define P_P   1
#define P_RW  2
#define P_US  4
#define P_PS  0x80
#ifdef ARCH_X86_64
typedef uint64_t pte_t;
static pte_t pml4[512] __attribute__((aligned(4096)));
static pte_t pdpt[512] __attribute__((aligned(4096)));
static pte_t pd[512] __attribute__((aligned(4096)));
void paging_init() {
    memset(pml4, 0, sizeof(pml4));
    memset(pdpt, 0, sizeof(pdpt));
    memset(pd, 0, sizeof(pd));
    for (int i = 0; i < 512; i++)
        pd[i] = (i * 0x200000) | P_P | P_RW | P_PS;
    pdpt[0] = (pte_t)pd | P_P | P_RW;
    pml4[0] = (pte_t)pdpt | P_P | P_RW;
    asm volatile("mov %0, %%cr3" : : "r"(pml4));
    uint64_t cr4; asm volatile("mov %%cr4,%0":"=r"(cr4)); cr4|=(1<<5); asm volatile("mov %0,%%cr4"::"r"(cr4));
    uint64_t cr0; asm volatile("mov %%cr0,%0":"=r"(cr0)); cr0|=(1<<31); asm volatile("mov %0,%%cr0"::"r"(cr0));
}
#else
typedef uint32_t pte_t;
static pte_t pd[1024] __attribute__((aligned(4096)));
static pte_t pt[1024] __attribute__((aligned(4096)));
void paging_init() {
    memset(pd, 0, sizeof(pd));
    memset(pt, 0, sizeof(pt));
    for (int i = 0; i < 1024; i++)
        pt[i] = (i * 0x1000) | P_P | P_RW;
    pd[0] = (pte_t)pt | P_P | P_RW;
    asm volatile("mov %0, %%cr3" : : "r"(pd));
    uint32_t cr0; asm volatile("mov %%cr0,%0":"=r"(cr0)); cr0|=0x80000000; asm volatile("mov %0,%%cr0"::"r"(cr0));
}
#endif

// =========================
// PIC/PIT
// =========================
#define PIC1      0x20
#define PIC1_DATA 0x21
#define PIC2      0xA0
#define PIC2_DATA 0xA1
void pic_remap() {
    uint8_t a1 = inb(PIC1_DATA), a2 = inb(PIC2_DATA);
    outb(PIC1, 0x11); outb(PIC2, 0x11);
    outb(PIC1_DATA, 0x20); outb(PIC2_DATA, 0x28);
    outb(PIC1_DATA, 4); outb(PIC2_DATA, 2);
    outb(PIC1_DATA, 0x01); outb(PIC2_DATA, 0x01);
    outb(PIC1_DATA, a1); outb(PIC2_DATA, a2);
}
void pit_init() {
    const uint32_t divisor = 1193180 / 100;
    outb(0x43, 0x36); outb(0x40, divisor & 0xFF); outb(0x40, (divisor >> 8) & 0xFF);
}

// =========================
// IDT/IRQ
// =========================
struct IDTEntry { uint16_t off_lo, sel; uint8_t zero, flags; uint16_t off_hi; } __attribute__((packed));
static struct IDTEntry idt[256];
static struct { uint16_t limit; uintptr_t base; } __attribute__((packed)) idtp;

extern void irq0_handler();
extern void irq1_handler();

#define SET_IDT(n, fn) do { \
    uintptr_t off = (uintptr_t)(fn); \
    idt[n].off_lo = off & 0xFFFF; \
    idt[n].sel = 0x08; \
    idt[n].zero = 0; \
    idt[n].flags = 0x8E; \
    idt[n].off_hi = (off >> 16) & 0xFFFF; \
} while(0)

void idt_init() {
    memset(idt, 0, sizeof(idt));
    SET_IDT(32, irq0_handler);
    SET_IDT(33, irq1_handler);
    idtp.limit = sizeof(idt) - 1;
    idtp.base = (uintptr_t)&idt;

    asm volatile("lidt (%0)" : : "r"(&idtp));
}

// =========================
// Scheduler
// =========================
#define MAX_TASKS 16
#define MAX_PRIORITY 10
#define MIN_PRIORITY 0
#define AGING_THRESHOLD 5

typedef enum {
    TASK_UNUSED,
    TASK_READY,
    TASK_RUNNING,
    TASK_SLEEPING,
    TASK_WAITING,
    TASK_ZOMBIE
} task_state_t;

typedef struct {
    int id;
    int active;
    int priority;
    int age;
    task_state_t state;
    uint8_t* stack; // pointer to stack memory
} task_t;

static task_t tasks[MAX_TASKS];
static int current_task = -1;

void scheduler_init() {
    for (int i = 0; i < MAX_TASKS; i++) {
        tasks[i].id = i;
        tasks[i].active = 0;
        tasks[i].priority = MIN_PRIORITY;
        tasks[i].age = 0;
        tasks[i].state = TASK_UNUSED;
        tasks[i].stack = NULL;
    }
}

void create_task(int priority) {
    for (int i = 0; i < MAX_TASKS; i++) {
        if (!tasks[i].active) {
            tasks[i].active = 1;
            tasks[i].priority = priority;
            tasks[i].age = 0;
            tasks[i].state = TASK_READY;
            tasks[i].stack = NULL; // TODO: Allocate stack here
            return;
        }
    }
}

void schedule_next_task() {
    int best_task = -1;
    int highest_score = -1;

    for (int i = 0; i < MAX_TASKS; i++) {
        if (tasks[i].active && tasks[i].state == TASK_READY) {
            int score = tasks[i].priority + tasks[i].age;
            if (score > highest_score) {
                highest_score = score;
                best_task = i;
            }
        }
    }

    if (best_task >= 0) {
        // Age others
        for (int i = 0; i < MAX_TASKS; i++) {
            if (i != best_task && tasks[i].active && tasks[i].state == TASK_READY) {
                tasks[i].age++;
                if (tasks[i].age > AGING_THRESHOLD && tasks[i].priority < MAX_PRIORITY) {
                    tasks[i].priority++;
                    tasks[i].age = 0;
                }
            }
        }

        // Switch to best task
        if (current_task != -1 && tasks[current_task].state == TASK_RUNNING) {
            tasks[current_task].state = TASK_READY;
        }
        current_task = best_task;
        tasks[current_task].state = TASK_RUNNING;
    } else {
        // No ready task — halt or idle
        asm volatile("hlt");
    }
}

// =========================
// IRQ Handlers
// =========================
void irq0_handler() {
    schedule_next_task();
    outb(0x20, 0x20); // End of interrupt
}

void irq1_handler() {
    outb(0x20, 0x20);
}

//=========================
// File_node - before other operations
//=========================

typedef struct file_node {
    char name[64];
    int node_type;

    struct file_node* parent;
    struct file_node* children;
    struct file_node* next_sibling;

    uint8_t* content;
    size_t size;
    size_t capacity;
} file_node_t;

// =========================
// Advanced Virtual Filesystem Layer (VFS)
// =========================

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Constants & limits
#define MAX_FILESYSTEMS 8
#define MAX_MOUNTS 8
#define MAX_OPEN_FILES 32
#define MAX_PATH_LEN 256

// Filesystem types
#define FS_EXT4      1
#define FS_SQUASHFS  8

// Node Types (file, dir, symlink)
#define NODE_TYPE_FILE      1
#define NODE_TYPE_DIRECTORY 2
#define NODE_TYPE_SYMLINK   3

// =========================
// File System Interface
// =========================

struct filesystem {
    const char* name;
    int fs_type;
    int (*mount)(const char*, const char*);
    int (*unmount)(const char*);
    int (*exec)(const char*);
    int (*open)(const char*, int*);
    int (*read)(int, void*, size_t);
    int (*write)(int, const void*, size_t);
    int (*close)(int);
};

// =========================
// Forward declarations
// =========================
typedef struct filesystem filesystem_t;
typedef struct mount_entry mount_entry_t;
typedef struct file_descriptor file_descriptor_t;

// =========================
// Mount entry linking mountpoints to filesystems
// =========================
struct mount_entry {
    const char* device;
    const char* mountpoint;
    filesystem_t* fs;
    int mounted;
};

// =========================
// Open file descriptor representation
// =========================
struct file_descriptor {
    mount_entry_t* mount;
    int fs_fd;       // FS-specific fd or node index
    int position;    // file read/write position
    int used;
};

// =========================
// Global VFS state
// =========================
static filesystem_t* registered_fs[MAX_FILESYSTEMS];
static int registered_fs_count = 0;

static mount_entry_t mounts[MAX_MOUNTS];
static int mounts_count = 0;

static file_descriptor_t open_files[MAX_OPEN_FILES];

// =========================
// Utility: Find FS by type
// =========================
static filesystem_t* vfs_find_fs_by_type(int fs_type) {
    for (int i = 0; i < registered_fs_count; i++) {
        if (registered_fs[i]->fs_type == fs_type)
            return registered_fs[i];
    }
    return NULL;
}

void serial_write(const char* str);

// =========================
// Register filesystem driver
// =========================
int vfs_register_fs(filesystem_t* fs) {
    if (registered_fs_count >= MAX_FILESYSTEMS) {
        serial_write("[VFS] Too many filesystems registered\n");
        return -1;
    }
    registered_fs[registered_fs_count++] = fs;
    serial_write("[VFS] Registered FS: ");
    serial_write(fs->name);
    serial_write("\n");
    return 0;
}

// =========================
// Mount filesystem on mountpoint
// =========================
int vfs_mount(const char* device, const char* mountpoint, int fs_type) {
    if (mounts_count >= MAX_MOUNTS) {
        serial_write("[VFS] Mount table full\n");
        return -1;
    }
    filesystem_t* fs = vfs_find_fs_by_type(fs_type);
    if (!fs) {
        serial_write("[VFS] FS type not found\n");
        return -1;
    }
    if (fs->mount(device, mountpoint) != 0) {
        serial_write("[VFS] FS mount failed\n");
        return -1;
    }
    mounts[mounts_count].device = device;
    mounts[mounts_count].mountpoint = mountpoint;
    mounts[mounts_count].fs = fs;
    mounts[mounts_count].mounted = 1;
    mounts_count++;
    serial_write("[VFS] Mounted ");
    serial_write(device);
    serial_write(" on ");
    serial_write(mountpoint);
    serial_write(" using ");
    serial_write(fs->name);
    serial_write("\n");
    return 0;
}

// =========================
// Find mount entry for a given absolute path (longest prefix match)
// =========================
static mount_entry_t* vfs_find_mount(const char* path) {
    mount_entry_t* best = NULL;
    size_t best_len = 0;
    for (int i = 0; i < mounts_count; i++) {
        if (!mounts[i].mounted) continue;
        size_t mlen = strlen(mounts[i].mountpoint);
        if (strncmp(path, mounts[i].mountpoint, mlen) == 0) {
            // Make sure it's an exact match or directory boundary
            if (path[mlen] == '/' || path[mlen] == '\0') {
                if (mlen > best_len) {
                    best = &mounts[i];
                    best_len = mlen;
                }
            }
        }
    }
    return best;
}

// =========================
// Path helper: Strip mountpoint prefix from path
// Returns pointer inside `path` after mountpoint prefix.
// =========================
static const char* vfs_strip_mountpoint(mount_entry_t* mount, const char* path) {
    size_t mlen = strlen(mount->mountpoint);
    if (strncmp(path, mount->mountpoint, mlen) == 0) {
        if (path[mlen] == '\0') return "/";
        return path + mlen;
    }
    return path;
}

// =========================
// Resolve a file_node* from a path inside the mounted FS
// Walks nodes from root_node using '/'-delimited components.
// =========================
static file_node_t* fs_resolve_path(file_node_t* root, const char* path) {
    if (!root || !path) return NULL;

    if (strcmp(path, "/") == 0) return root;

    // Skip leading slash
    if (path[0] == '/') path++;

    file_node_t* current = root;
    char component[64];
    size_t comp_len = 0;
    const char* p = path;

    while (*p) {
        comp_len = 0;
        while (*p && *p != '/' && comp_len < sizeof(component) - 1) {
            component[comp_len++] = *p++;
        }
        component[comp_len] = '\0';

        // Search for component in current's children
        file_node_t* child = current->children;
        while (child) {
            if (strcmp(child->name, component) == 0) {
                current = child;
                break;
            }
            child = child->next_sibling;
        }

        if (!child) {
            return NULL; // component not found
        }

        if (*p == '/') p++; // skip slash
    }

    return current;
}

// =========================
// VFS exec - execute a file at absolute path
// =========================
int vfs_exec(const char* path) {
    mount_entry_t* mount = vfs_find_mount(path);
    if (!mount) {
        serial_write("[VFS] Exec no mount for ");
        serial_write(path);
        serial_write("\n");
        return -1;
    }
    const char* subpath = vfs_strip_mountpoint(mount, path);
    return mount->fs->exec(subpath);
}

// =========================
// VFS open - open file, return VFS fd
// =========================
int vfs_open(const char* path) {
    mount_entry_t* mount = vfs_find_mount(path);
    if (!mount) {
        serial_write("[VFS] Open no mount for ");
        serial_write(path);
        serial_write("\n");
        return -1;
    }
    const char* subpath = vfs_strip_mountpoint(mount, path);

    int fs_fd = -1;
    if (mount->fs->open(subpath, &fs_fd) != 0) {
        serial_write("[VFS] Open failed in FS\n");
        return -1;
    }

    // Find free slot in open_files
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (!open_files[i].used) {
            open_files[i].used = 1;
            open_files[i].mount = mount;
            open_files[i].fs_fd = fs_fd;
            open_files[i].position = 0;
            return i;
        }
    }

    serial_write("[VFS] Open file table full\n");
    if (mount->fs->close) mount->fs->close(fs_fd);
    return -1;
}

// =========================
// VFS read - read file contents
// =========================
int vfs_read(int vfs_fd, void* buffer, size_t size) {
    if (vfs_fd < 0 || vfs_fd >= MAX_OPEN_FILES || !open_files[vfs_fd].used) {
        serial_write("[VFS] Invalid read fd\n");
        return -1;
    }
    mount_entry_t* mount = open_files[vfs_fd].mount;
    if (!mount->fs->read) return -1;

    int bytes_read = mount->fs->read(open_files[vfs_fd].fs_fd, buffer, size);
    if (bytes_read > 0)
        open_files[vfs_fd].position += bytes_read;
    return bytes_read;
}

// =========================
// VFS close - close opened file
// =========================
int vfs_close(int vfs_fd) {
    if (vfs_fd < 0 || vfs_fd >= MAX_OPEN_FILES || !open_files[vfs_fd].used) {
        serial_write("[VFS] Invalid close fd\n");
        return -1;
    }
    mount_entry_t* mount = open_files[vfs_fd].mount;
    if (mount->fs->close)
        mount->fs->close(open_files[vfs_fd].fs_fd);
    open_files[vfs_fd].used = 0;
    return 0;
}

// =========================
//  EXT4 FS Implementation (in-memory)
// =========================

static file_node_t ext4_root;
static file_node_t ext4_bin;
static file_node_t ext4_init;

// Helper to link nodes
static void fs_add_child(file_node_t* parent, file_node_t* child) {
    if (!parent->children) {
        parent->children = child;
    } else {
        file_node_t* last = parent->children;
        while (last->next_sibling) last = last->next_sibling;
        last->next_sibling = child;
    }
    child->parent = parent;
}

// Mount for EXT4 - create minimal tree
int ext4_mount(const char* device, const char* mountpoint) {
    (void)mountpoint;
    serial_write("[EXT4] Mount device ");
    serial_write(device);
    serial_write("\n");

    // Setup root directory
    memset(&ext4_root, 0, sizeof(ext4_root));
    strcpy(ext4_root.name, "/");
    ext4_root.node_type = NODE_TYPE_DIRECTORY;

    // Setup /bin directory
    memset(&ext4_bin, 0, sizeof(ext4_bin));
    strcpy(ext4_bin.name, "bin");
    ext4_bin.node_type = NODE_TYPE_DIRECTORY;
    fs_add_child(&ext4_root, &ext4_bin);

    // Setup /bin/init file
    static const uint8_t init_content[] = "EXT4 Init executable stub\n";
    memset(&ext4_init, 0, sizeof(ext4_init));
    strcpy(ext4_init.name, "init");
    ext4_init.node_type = NODE_TYPE_FILE;
    ext4_init.content = (uint8_t*)init_content;
    ext4_init.size = sizeof(init_content) - 1;
    fs_add_child(&ext4_bin, &ext4_init);

    return 0;
}

int ext4_unmount(const char* mountpoint) {
    (void)mountpoint;
    serial_write("[EXT4] Unmount\n");
    return 0;
}

// =========================
// SquashFS Implementation
// =========================

static file_node_t squashfs_root;
static file_node_t squashfs_readme;

static file_node_t* squashfs_resolve_path(const char* path) {
    if (!path || strcmp(path, "/") == 0) return &squashfs_root;

    if (path[0] == '/') path++;

    if (strcmp(path, squashfs_readme.name) == 0) return &squashfs_readme;

    return NULL;
}

int squashfs_exec(const char* path) {
    file_node_t* node = squashfs_resolve_path(path);
    if (!node) {
        serial_write("[SquashFS] Exec: file not found: ");
        serial_write(path);
        serial_write("\n");
        return -1;
    }
    if (node->node_type != NODE_TYPE_FILE) {
        serial_write("[SquashFS] Exec: not a file: ");
        serial_write(path);
        serial_write("\n");
        return -1;
    }
    serial_write("[SquashFS] Executing ");
    serial_write(path);
    serial_write("\n");
    return 0;
}

int squashfs_open(const char* path, int* out_fd) {
    file_node_t* node = squashfs_resolve_path(path);
    if (!node) return -1;
    *out_fd = (int)(uintptr_t)node;
    return 0;
}

int squashfs_read(int fd, void* buffer, size_t size) {
    file_node_t* node = (file_node_t*)(uintptr_t)fd;
    if (!node || node->node_type != NODE_TYPE_FILE) return -1;

    size_t to_read = (size < node->size) ? size : node->size;
    memcpy(buffer, node->content, to_read);
    return (int)to_read;
}

int squashfs_write(int fd, const void* buffer, size_t size) {
    file_node_t* node = (file_node_t*)(uintptr_t)fd;
    if (!node || node->node_type != NODE_TYPE_FILE) return -1;

    if (size > node->capacity) {
        size_t new_capacity = ((size + 511) / 512) * 512;
        uint8_t* new_buf = (uint8_t*)realloc(node->content, new_capacity);
        if (!new_buf) return -1;
        node->content = new_buf;
        node->capacity = new_capacity;
    }

    memcpy(node->content, buffer, size);
    node->size = size;
    return (int)size;
}

int squashfs_close(int fd) {
    (void)fd;
    return 0;
}

int squashfs_mount(const char* device, const char* mountpoint) {
    serial_write("[SquashFS] Mount called\n");

    memset(&squashfs_root, 0, sizeof(squashfs_root));
    strcpy(squashfs_root.name, "/");
    squashfs_root.node_type = NODE_TYPE_DIRECTORY;

    static const uint8_t readme_content[] = "SquashFS Readme content\n";
    memset(&squashfs_readme, 0, sizeof(squashfs_readme));
    strcpy(squashfs_readme.name, "README");
    squashfs_readme.node_type = NODE_TYPE_FILE;
    squashfs_readme.content = (uint8_t*)readme_content;
    squashfs_readme.size = sizeof(readme_content) - 1;
    squashfs_readme.capacity = 0;

    fs_add_child(&squashfs_root, &squashfs_readme);
    return 0;
}

int squashfs_unmount(const char* mountpoint) {
    serial_write("[SquashFS] Unmount called\n");
    (void)mountpoint;
    return 0;
}

filesystem_t squashfs_fs = {
    .name = "squashfs",
    .fs_type = 8,
    .mount = squashfs_mount,
    .unmount = squashfs_unmount,
    .exec = squashfs_exec,
    .open = squashfs_open,
    .read = squashfs_read,
    .write = squashfs_write,
    .close = squashfs_close,
};

// =========================
// Kernel Entry Point Binary
// =========================
// Constants for filesystems
#define FS_EXT4    1
#define FS_EXT2    2
#define FS_FAT32   3
#define FS_NTFS    4
#define FS_FAT16   5
#define FS_FAT12   6
#define FS_EXFAT   7

// Task states
#define TASK_RUNNING 1
#define TASK_WAITING 2


// Forward declarations of external variables and functions
extern void serial_init(void);
extern void serial_write(const char*);
extern void heap_init(void);
extern void paging_init(void);
extern void idt_init(void);
extern void pic_remap(void);
extern void pit_init(void);

extern int vfs_mount(const char* device, const char* mount_point, int fs_type);
extern void register_fs(void* fs);

extern void scheduler_init(void);
extern void schedule_next_task(void);

// Filesystem structs
extern void* ext2_fs;
extern void* ntfs_fs;
extern void* fat12_fs;
extern void* fat16_fs;
extern void* fat32_fs;
extern void* exfat_fs;

// Task struct and variables
typedef struct {
    int active;
    int priority;
    int state;
    void* stack;
} task_t;

extern task_t tasks[MAX_TASKS];
extern int current_task;

// Kernel Entry Point Binary
void kernel_main(void* core_squashfs_addr) {
    serial_init();
    serial_write("\n=== BudgieX Kernel Boot ===\n");

#ifdef ARCH_X86_64
    serial_write("[+] Mode: 64-bit\n");
#else
    serial_write("[+] Mode: 32-bit\n");
#endif

    heap_init();
    paging_init();
    idt_init();
    pic_remap();
    pit_init();

    // Register filesystems
    register_fs(&ext4_fs);
    register_fs(&ext2_fs);
    register_fs(&ntfs_fs);
    register_fs(&fat12_fs);
    register_fs(&fat16_fs);
    register_fs(&fat32_fs);
    register_fs(&exfat_fs);
    serial_write("[+] Filesystems registered\n");

    // Try mounting root filesystem with fallback logic
    const char* devices[] = { "/dev/sda1", "/dev/hda1" };
    int fs_types[] = { FS_EXT4, FS_EXT2, FS_FAT32, FS_NTFS, FS_FAT16, FS_FAT12, FS_EXFAT };
    int mounted = 0;

    for (int i = 0; i < (sizeof(devices)/sizeof(devices[0])) && !mounted; ++i) {
        for (int j = 0; j < (sizeof(fs_types)/sizeof(fs_types[0])) && !mounted; ++j) {
            if (vfs_mount(devices[i], "/", fs_types[j]) >= 0) {
                mounted = 1;
            }
        }
    }

    if (!mounted) {
        serial_write("[FATAL] Failed to mount root FS\n");
        while (1) asm volatile("cli; hlt");
    }

    serial_write("[+] Root filesystem mounted\n");

    // Initialize scheduler and tasks
    scheduler_init();

    // Setup example tasks
    tasks[0].active = 1; tasks[0].priority = 5; tasks[0].state = TASK_RUNNING; tasks[0].stack = NULL;
    tasks[1].active = 1; tasks[1].priority = 2; tasks[1].state = TASK_WAITING; tasks[1].stack = NULL;
    tasks[2].active = 1; tasks[2].priority = 8; tasks[2].state = TASK_WAITING; tasks[2].stack = NULL;
    current_task = 0;

    serial_write("[+] Tasks initialized (T0=5, T1=2, T2=8)\n");

    asm volatile("sti");

    while (1) {
        schedule_next_task();
        asm volatile("hlt");
    }
}

// =========================
// Project Dedication
// =========================
static const char* dummy_padding[] = {
    "BudgieX 26.03 NOSP is the latest release.",
    "This kernel was created by a 14 year old with a dream.",
    "It was made with passion and empathy and tons of hard work.",
    "The kernel supports multitasking, paging, VFS, and IRQs.",
    "Serial debugging helps trace kernel boot steps.",
    "Heap allocator manages dynamic memory for kernel subsystems.",
    "Scheduler uses priority and aging for task selection.",
    "IRQ0 triggers the scheduler for preemptive multitasking.",
    "Multiple filesystems can be registered and mounted.",
    "Paging setup enables virtual memory with 4MB or 4KB pages.",
    "PIC and PIT are remapped and initialized for interrupts.",
    "IDT stores interrupt handlers and is loaded during init.",
    "Tasks have states and priorities managed by the scheduler.",
    "This is a minimal but expandable kernel framework.",
    "Feel Free to explore my custom OS.",
    "       2025 BudgieX Corp.",
    "      All Rights Reserved",
    NULL
};

static void kernel_padding() {
    for (int i = 0; dummy_padding[i] != NULL; i++) {
        serial_write(dummy_padding[i]);
        serial_write("\n");
    }
}

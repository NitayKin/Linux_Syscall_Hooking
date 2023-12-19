#include <linux/kprobes.h>

#define NUM_OF_HOOKED_SYSCALLS 2

// decleration of our functions
static asmlinkage unsigned long open_syscall_hook(const struct pt_regs *);
static asmlinkage unsigned long openat_syscall_hook(const struct pt_regs *); 

static uid_t uid;

//location of the syscall table
static unsigned long **sys_call_table_p;

//list of all the numbers of the syscalls being hooked
static unsigned short hooked_syscalls_numbers[NUM_OF_HOOKED_SYSCALLS] = {__NR_openat, __NR_open};

//list of all the original func pointers of the syscalls
static asmlinkage long (*syscalls_original_func_p[NUM_OF_HOOKED_SYSCALLS])(const struct pt_regs *);

// for each syscall, this enum gives the appropriate index in the above tables
typedef enum {OPENAT_FUNC_INDEX = 0, OPEN_FUNC_INDEX = 1} syscall_func_index;

// list of our defined functions that will override the originals
unsigned long (*hooks_func_list[NUM_OF_HOOKED_SYSCALLS])(const struct pt_regs *) = {openat_syscall_hook, open_syscall_hook};


static asmlinkage unsigned long open_syscall_hook(const struct pt_regs *regs) 
{ 
#define READ_ONLY 0
#define WRITE_ONLY 1
#define READ_WRITE 2

    int i = 0;
    unsigned int mode_bitfield = regs->si & 0x3;
    char file_name[256];
    char *mode = (mode_bitfield & O_RDWR) ? "READ WRITE" : ((mode_bitfield & O_WRONLY) ? "WRITE ONLY" : "READ ONLY");
    uid = __kuid_val(current_uid());

    do {
        get_user(*(file_name+i), (char __user *)regs->di + i);
        i++; 
    } while ( *(file_name+i-1) != '\0' && i < 255 );

    if( uid != 0 && strnstr(file_name,"Desktop",strlen(file_name)) != NULL){
        pr_info("open() syscall: mode %s by uid:%d file name:%s", mode ,uid ,file_name);
    }

    return syscalls_original_func_p[OPEN_FUNC_INDEX](regs);
} 



static asmlinkage unsigned long openat_syscall_hook(const struct pt_regs *regs) 
{ 
#define READ_ONLY 0
#define WRITE_ONLY 1
#define READ_WRITE 2

    int i = 0;
    unsigned int mode_bitfield = regs->dx & 0x3;
    char file_name[256];
    char *mode = (mode_bitfield & O_RDWR) ? "READ WRITE" : ((mode_bitfield & O_WRONLY) ? "WRITE ONLY" : "READ ONLY");
    uid = __kuid_val(current_uid());

    do {
        get_user(*(file_name+i), (char __user *)regs->si + i);
        i++; 
    } while ( *(file_name+i-1) != '\0' && i < 255 );

    if( uid != 0 && strnstr(file_name,"Desktop",strlen(file_name)) != NULL){
        pr_info("openat() syscall: mode %s by uid:%d file name:%s", mode ,uid ,file_name);
    }

    return syscalls_original_func_p[OPENAT_FUNC_INDEX](regs);
} 

static unsigned long **find_sys_call_table_p(void) 
{ 
    unsigned long (*kallsyms_lookup_name)(const char *name); 
    struct kprobe kp = { 
        .symbol_name = "kallsyms_lookup_name", 
    }; 

    if (register_kprobe(&kp) < 0) 
        return NULL; 

    kallsyms_lookup_name = (unsigned long (*)(const char *name))kp.addr; 
    unregister_kprobe(&kp); 

    return (unsigned long **)kallsyms_lookup_name("sys_call_table"); 
} 

static inline void __write_cr0(unsigned long cr0) 
{ 

    asm volatile("mov %0,%%cr0" : "+r"(cr0) : : "memory"); 
} 

static void enable_write_protection(void) 
{ 
    unsigned long cr0 = read_cr0(); 
    set_bit(16, &cr0); 
    __write_cr0(cr0); 
} 

static void disable_write_protection(void) 
{ 
    unsigned long cr0 = read_cr0(); 
    clear_bit(16, &cr0); 
    __write_cr0(cr0); 
} 

static int __init hook_start(void) 
{ 
    if (!(sys_call_table_p = find_sys_call_table_p())) 
        return -1;

    disable_write_protection();

    for(int i = 0; i < NUM_OF_HOOKED_SYSCALLS; ++i){
        // save the origin func pointer, return to it if the kernel module will be removed by rmmod
        syscalls_original_func_p[i] = (void *)sys_call_table_p[hooked_syscalls_numbers[i]];
        // put our function in the appropriate location in the syscall table
        sys_call_table_p[hooked_syscalls_numbers[i]] = (unsigned long *)hooks_func_list[i];
    }

    enable_write_protection();
    return 0;
}

static void __exit hook_end(void) 
{
    disable_write_protection();
    for(int i = 0; i < NUM_OF_HOOKED_SYSCALLS; ++i)
        sys_call_table_p[hooked_syscalls_numbers[i]] = (unsigned long *)syscalls_original_func_p[i]; 
    
    enable_write_protection(); 
    pr_alert("Finite Incantatem");
}

module_init(hook_start); 
module_exit(hook_end); 
MODULE_LICENSE("GPL");
#include <linux/kprobes.h>

static uid_t uid;
static unsigned long **sys_call_table_p;
static asmlinkage long (*original_func_p)(const struct pt_regs *); 

static asmlinkage long open_syscall_hook(const struct pt_regs *regs) 
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
        pr_info("Opened mode %s by uid:%d file name:%s", mode ,uid ,file_name);
    }

    return original_func_p(regs);
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
    original_func_p = (void *)sys_call_table_p[__NR_openat]; 
    sys_call_table_p[__NR_openat] = (unsigned long *)open_syscall_hook; 
    enable_write_protection(); 
    return 0; 
} 

static void __exit hook_end(void) 
{
    disable_write_protection(); 
    sys_call_table_p[__NR_openat] = (unsigned long *)original_func_p; 
    enable_write_protection(); 
    pr_alert("Finite Incantatem");
} 

module_init(hook_start); 
module_exit(hook_end); 
MODULE_LICENSE("GPL");
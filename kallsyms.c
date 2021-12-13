//https://github.com/h33p/kallsyms-lp
#include <linux/module.h>
#include <linux/completion.h>
#include <linux/list.h>
#include <linux/version.h>

#if IS_ENABLED(CONFIG_KPROBES)
#include "kallsyms_kp.c"
#elif IS_ENABLED(CONFIG_LIVEPATCH)
#include "kallsyms_lp.c"
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)
int init_kallsyms(void) {
	return 0;
}
#else
#error "No suitable kallsyms acquisition method!"
#endif

int kallsyms_lookup_fault(const char *sym) {
	printk("kallsyms_lookup_name failed for: %s\n", sym);
	return -EBADF;
}

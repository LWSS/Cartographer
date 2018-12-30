#include <linux/ftrace.h>
#include <linux/proc_fs.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <asm/uaccess.h> //copy_from_user

MODULE_DESCRIPTION("");
MODULE_AUTHOR("");
MODULE_LICENSE("GPL");

/* file created in /proc/ */
#define PROC_FILENAME "cartographer"

#ifndef CONFIG_X86_64
    #error Only x86_64 architecture is supported!
#endif

/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0


/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
    #pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

static DEFINE_MUTEX(data_mutex);

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

struct cart_settings {
    char *target_lib;
    bool null_file;
    bool remove_entry;
    bool spoof_permissions;
    u8 permissions;
};
static struct cart_settings settings;

static int init_hook( struct ftrace_hook *hook )
{
    hook->address = kallsyms_lookup_name(hook->name);

    if (!hook->address) {
        printk("unresolved fn symbol: %s\n", hook->name);
        return -ENOENT;
    } else {
        printk("Found fn %s at %p\n", hook->name, (void*)hook->address);
    }

#if USE_FENTRY_OFFSET
    *((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
    *((unsigned long*) hook->original) = hook->address;
#endif

    return 0;
}

static void notrace ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
    regs->ip = (unsigned long) hook->function;
#else
    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long) hook->function;
#endif
}

static asmlinkage void (*orig_show_map_vma)(struct seq_file *m,
                                          struct vm_area_struct *vma);

static asmlinkage void cart_show_map_vma(struct seq_file *m,
                                         struct vm_area_struct *vma)
{
    if( !vma || !vma->vm_file ) {
        return orig_show_map_vma( m, vma );
    }

    /* Only interested in our target lib */
    if( strcmp(vma->vm_file->f_path.dentry->d_iname, settings.target_lib) != 0 ){
        return orig_show_map_vma( m, vma );
    }

    struct file *file_backup = vma->vm_file;
    unsigned long backup_flags = vma->vm_flags;

    if( settings.remove_entry ){ // in some cases the memory offset makes this kinda obvious, but it seems there's gaps naturally too sometimes.
        printk("show_map_vma Hook - removing entry in maps (%s)\n", vma->vm_file->f_path.dentry->d_iname);
        return;
    }
    if( settings.null_file ){
        printk("show_map_vma Hook - removing file on (%s)\n", vma->vm_file->f_path.dentry->d_iname);
        vma->vm_file = NULL;
    }

    if( settings.spoof_permissions ){
        printk("show_map_vma Hook - Setting permissions on (%s)\n", vma->vm_file->f_path.dentry->d_iname);
        vma->vm_flags &= ~VM_READ;
        vma->vm_flags &= ~VM_WRITE;
        vma->vm_flags &= ~VM_EXEC;

        vma->vm_flags |= settings.permissions;
    }


    orig_show_map_vma( m, vma );

    vma->vm_flags = backup_flags;
    vma->vm_file = file_backup;
}

static ssize_t on_write(struct file *file, const char *buf, size_t len, loff_t *pos)
{
    u8 res; //perms
    int err;

    /* not sure if this mutex is needed. */
    mutex_lock(&data_mutex);

    if( !buf ){
        printk("Buffer is NULL. hmmm....\n");
        goto end;
    }
    /* strsep changes the string, buf is constant, need to copy */
    char *backup = kmalloc(len, GFP_KERNEL);
    if( !backup ){
        printk("Failed to malloc %ld bytes for argument parsing!\n", len);
        goto end;
    }
    err = strncpy_from_user(backup, buf, len);
    if( err < 0 ){
        printk("Error copying arguments from userspace! (code: %d)\n", err);
        goto end;
    }
    backup[len - 1] = '\0';
    /* Get First word for command */
    char *word = strsep( &backup, " ,\n\t" );
    if( strstr(word, "settarget") ){
        word = strsep( &backup, " ,\n\t" );
        if( !word ){
            printk( "settarget requires an argument! ( the target lib )\n");
            goto end;
        }
        if( strlen(word) >= 63 ){
            printk( "target_lib max size is 64! make your name smaller or edit the source\n" );
            goto end;
        }
        strncpy( settings.target_lib, word, 62 );
        printk( "target_lib set to: %s\n", settings.target_lib );
    } else if( strstr(word, "setspoofperms") ){
        word = strsep( &backup, " ,\n\t" );
        if( !word ){
            printk( "setspoofperms requires an argument! ( the permission #, VM_READ - 1, VM_WRITE - 2, VM_EXEC - 4 )" );
            goto end;
        }
        err = kstrtos8( word, 10, &res );
        if( err || ( res < 0 || res > 7 ) ){
            printk( "setspoofperms: %s is an invalid argument! Valid is [0-7]\n", word );
            goto end;
        }

        settings.permissions = res;
        printk("spoof perms set to %u\n", res);
    } else if( strstr(word, "nullfile") ){
        if( settings.null_file ){
            printk("nullfile is already on! Please turn it off or reload\n");
            goto end;
        }
        if( !settings.target_lib ){
            printk("nullfile requires target_lib to be set ( see the settarget command )\n");
            goto end;
        }

        settings.null_file = true;
        printk("nullfile Activated.\n");
    } else if( strstr( word, "removeentry" ) ){
        if( settings.remove_entry ){
            printk("removeentry is already on! Please turn it off or reload\n");
            goto end;
        }
        if( !settings.target_lib ){
            printk("removeentry requires the target_lib to be set ( see the settarget command )\n");
            goto end;
        }
        settings.remove_entry = true;
        printk("removeentry Activated.\n");
    } else if( strstr( word, "spoofperms" ) ){
        if( settings.spoof_permissions ){
            printk("spoofpermissions is already on! Please turn it off or reload\n");
            goto end;
        }

        /* Spoof permissions can be Zero */
        settings.spoof_permissions = true;
        printk("spoofpermissions Activated.\n");
    } else if( strstr( word, "turnoff" ) ){
        word = strsep( &backup, " ,\n\t" );
        if( !word ){
            printk("turnoff requires an argument! ( the feature to turn off )\n");
            goto end;
        }
        if( strstr( word, "nullfile" ) ){
            printk("turning off nullfile.\n");
            settings.null_file = false;
        } else if( strstr( word, "removeentry" ) ){
            printk("turning off removeentry.\n");
            settings.remove_entry = false;
        } else if( strstr( word, "spoofpermissions" ) ){
            printk("turning off spoofpermissions.\n");
            settings.spoof_permissions = false;
        }
    } else {
        printk("Unrecognized Option!\n");
        goto end;
    }

end:
    if( backup ){
        kfree(backup);
    }
    mutex_unlock(&data_mutex);
    return len;
}

static struct ftrace_hook show_map_vma_hook;
static struct file_operations file_ops;

static int cart_startup(void)
{
    printk("Cartographer Loaded.\n");

    show_map_vma_hook.name = "show_map_vma";
    show_map_vma_hook.function = cart_show_map_vma;
    show_map_vma_hook.original = &orig_show_map_vma;
    int ret = init_hook( &show_map_vma_hook );

    if( ret )
        return ret;

    show_map_vma_hook.ops.func = ftrace_thunk;
    show_map_vma_hook.ops.flags = FTRACE_OPS_FL_SAVE_REGS
                                  | FTRACE_OPS_FL_RECURSION_SAFE
                                  | FTRACE_OPS_FL_IPMODIFY;

    ret = ftrace_set_filter_ip(&show_map_vma_hook.ops, show_map_vma_hook.address, 0, 0);
    if( ret ){
        printk("ftrace_set_filter_ip() failed: %d\n", ret);
        return ret;
    }

    ret = register_ftrace_function(&show_map_vma_hook.ops);
    if (ret) {
        printk("register_ftrace_function() failed: %d\n", ret);
        ftrace_set_filter_ip(&show_map_vma_hook.ops, show_map_vma_hook.address, 1, 0);
        return ret;
    }

    struct proc_dir_entry *entry = proc_create(PROC_FILENAME, 0, NULL, &file_ops);
    if( !entry ){
        printk("proc_create failed! is NULL\nUnload and try again!\n");
        return -EUCLEAN;
    }

    settings.target_lib = kmalloc(sizeof(char) * 64, GFP_KERNEL);

    if( !settings.target_lib ){
        printk("Failed to allocate Memory for libname(init)\n");
        return -ENOMEM;
    }

    file_ops.owner = THIS_MODULE;
    file_ops.write = on_write;

    return 0;
}

static void cart_shutdown(void)
{
    int ret;
    ret = unregister_ftrace_function(&show_map_vma_hook.ops);
    if( ret )
        printk("unregister_ftrace_function() failed: %d\n", ret);

    ret = ftrace_set_filter_ip(&show_map_vma_hook.ops, show_map_vma_hook.address, 1, 0);
    if( ret )
        printk("ftrace_set_filter_ip() failed: %d\n", ret);

    remove_proc_entry(PROC_FILENAME, NULL);

    if( settings.target_lib ){
        kfree(settings.target_lib);
    }

    printk("Cartographer UnLoaded.\n");
}

module_init(cart_startup);
module_exit(cart_shutdown);
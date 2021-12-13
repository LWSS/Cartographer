<p align="center">
<img src="https://i.imgur.com/kaY6nqc.jpg">
</p>

# The Cartographer

## What is it
Cartographer is a linux kernel module that is able to modify and hide linux memory maps from userspace.

## Update for Kernel >= 5.7
Kernel 5.7 stops the export of kallsyms functions and has forced us to change the way we get symbol addresses.

The new method by [heep](https://github.com/h33p/kallsyms-lp) requires Kernel 5.0 or higher and uses either the livepatcher or the kprobe feature based on the module info set in cartographer.c

## System Requirements
* 64bit Linux system
* Kernel Version >= 5.00( for Kernel Livepatch )
* The following Kernel Build configurations
	* CONFIG_FTRACE
	* CONFIG_KALLSYMS
	* CONFIG_DYNAMIC_FTRACE_WITH_REGS
	* CONFIG_HAVE_FENTRY
	* CONFIG_LIVEPATCH

Your distro provider probably put a list of your config options in `/boot/config*`, there's a good chance your kernel already has these options, but if it does not, you'll have to rebuild from source.
* Kernel headers for your current kernel.
* elfutils development package ( "elfutils-libelf-devel" for redhat, "libelf-dev" for ubuntu )
* Development Essentials ( make, gcc, etc. )

## Build Instructions
*  After installing kernel headers, you should just be able to use the makefile.
* `make` in the cartographer directory.

## AUR Installation
* You can install Cartographer by using the AUR helper of your choice and the package [cartographer-dkms-git](cartographer-dkms-git)
* Load the module by using `sudo modprobe cartographer_module`

## How to Use
You can see all the output Cartographer makes in the kernel log with `dmesg --follow` or if you don't have dmesg, `tail -f` the appropriate log in /var/log

After you have built Cartographer, you will need to load it. Since it is a kernel module, it has to be done by root.

`sudo insmod cartographer_module.ko`

Cartographer is very verbose and should tell you in the logs if something went wrong.

After the module is loaded, it is now ready for commands.
## Commands for Cartographer
When the module is loaded, it creates a file in /proc/ (`/proc/cartographer`) that handles all input. ( see PROC_FILENAME in the code if you wish to change this ).

*Note: Only the root user is allowed to send input to Cartographer.*

Commands are sent to Cartogarpher like this
`[root@localhost]# echo "$COMMAND ..." > /proc/cartographer`

The following commands are recognized by the program.
* **settarget**
	Sets the exact target filename to look for.
	This is required to be set first before any of the features will work.
* **setspoofperms**
	Sets the permission level for the spoofperms feature. ( Accepts 0 - 7 )
	VM_READ - 1, VM_WRITE - 2, VM_EXEC - 4
* **nullfile**
	This will leave the entry in the map, but will remove the associated file.
	A.K.A. Make it look like an anonymous mmap
* **removeentry**
	This will prevent the entry from showing in the maps. ( Used in example )
* **spoofperms**
	This will change the permissions shown in the maps entry(rwx). setspoofperms is required first.
* **turnoff**
	This followed by a feature name (nullfile/removeentry/spoofperms) will turn off the feature.


To unload the module, use `rmmod cartographer` ( as root still ). All features will be disabled.

## Example
I'll show you an example of removeentry.
First set the target library( this is just some random one I picked )

`echo "settarget libgio-2.0.so.0.5800.2" > /proc/cartographer`

Then enable the feature

`echo "removeentry" > /proc/cartographer`

Before:
<p align="center">
<img src="https://i.imgur.com/fISekdt.png">
</p>

After:
<p align="center">
<img src="https://i.imgur.com/Mr2Pak1.png">
</p>

## Credits

-Alexey Lozovsky - For his series of articles [part1](https://www.apriorit.com/dev-blog/544-hooking-linux-functions-1) about ftrace and hooking with ftrace along with code snippets that I used in this project.

-[Heep](https://github.com/greenbytesoftware) for the Idea of changing maps this way, and for the new livepatch symbol resolving method.

-[aw1cks](https://github.com/aw1cks) for the new AUR package.

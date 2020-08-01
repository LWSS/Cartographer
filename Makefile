KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build

obj-m += cartographer_module.o
cartographer_module-objs := cartographer.o kallsyms.o

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

noclean:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean

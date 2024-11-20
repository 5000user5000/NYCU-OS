obj-m += kfetch.o

# Kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build

# Phony targets for cleaning, loading, and unloading
.PHONY: all clean load unload

# Default target: build the module
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Clean target: remove built files
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Load target: insert the kernel module
load: all
	sudo insmod kfetch.ko

# Unload target: remove the kernel module
unload:
	sudo rmmod kfetch

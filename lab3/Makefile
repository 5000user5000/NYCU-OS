obj-m += kfetch_mod_313551118.o

# Kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build

# Phony targets
.PHONY: all clean load unload test

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	gcc -o kfetch kfetch.c

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f kfetch

load: all
	sudo insmod kfetch_mod_313551118.ko

unload:
	sudo rmmod kfetch_mod_313551118

test: load
	sudo ./kfetch -h
	sudo ./kfetch -a
	sudo ./kfetch -c -m
	sudo ./kfetch -n -p
	sudo ./kfetch -r -u
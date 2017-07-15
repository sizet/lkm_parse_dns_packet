# ©.

CC_FLAGS = -Wall

export EXTRA_CFLAGS = $(CC_FLAGS)

SOURCE_FILE = parse_dns_packet.c
OBJECT_FILE = $(SOURCE_FILE:.c=.o)
TARGET_FILE = $(SOURCE_FILE:.c=.ko)

KERNEL_PATH = /lib/modules/$(shell uname -r)/build

obj-m := $(OBJECT_FILE)


all:
	$(MAKE) -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_PATH) M=$(PWD) clean
	rm -rf Module.symvers *.mod.c *.ko *.o *~

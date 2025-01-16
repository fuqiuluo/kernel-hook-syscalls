SRCS :=mydaat.c mmuhack.c kallsyms.c hacktask.c nla.c server.c

MODULE = daat

obj-m :=$(MODULE).o
$(MODULE)-objs += mydaat.o
$(MODULE)-objs += mmuhack.o
$(MODULE)-objs += hacktask.o
$(MODULE)-objs += kallsyms.o
$(MODULE)-objs += server.o
$(MODULE)-objs += syscalls.o
$(MODULE)-objs += fnla.o

all:
	make -C $(KDIR) EXTRA_CGLAGS=-fno-pic M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
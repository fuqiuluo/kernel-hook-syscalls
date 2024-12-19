SRCS :=mydaat.c mmuhack.c kallsyms.c kprobe_all.c

MODULE = daat

obj-m :=$(MODULE).o
$(MODULE)-objs += mydaat.o
$(MODULE)-objs += mmuhack.o
$(MODULE)-objs += kallsyms.o
$(MODULE)-objs += kprobe_all.o

all:
	make -C $(KDIR) EXTRA_CGLAGS=-fno-pic M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
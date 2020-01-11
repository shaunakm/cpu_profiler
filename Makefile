## [M1: point 1]
#  ex4 (Externel module to be built)  is assigned to the MODULE
#  ...
MODULE	 = cpu_profiler

## [M2: point 1]
# The command specifies MODULE (ex4) files which are built as loadable kernel modules.
#  ...
obj-m += $(MODULE).o

## [M3: point 1]
#  Assigns build directory of the current kernel to the 'KERNELDIR' 
#  ...
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

## [M4: point 1]
#  Stores the Present Working Directory in PWD variable
#  ...
PWD := $(shell pwd)

## [M5: point 1]
#  When make is executed without arguments, the first goal encountered
#  will be built. In the top level Makefile the first goal present
#  is 'all:'. Hence 'ex4' module will be built when make is executed
#  without any arguments
#  ...
all: $(MODULE)

## [M6: point 1]
#  Makes object file for every '.c' file
#  ...
%.o: %.c
	@echo "  CC      $<"
	@$(CC) -c $< -o $@  

## [M7: point 1]
#  The command is used to build an external module against the running kernel
#  ...
$(MODULE):
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules 

## [M8: point 1]
#  Remove all generated files in the module directory only
#  ...
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

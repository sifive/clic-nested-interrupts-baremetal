# clic-nested-interrupts-baremetal
A low level example showing how to use GCC interrupt attribute and different CLIC interrupt levels to allow interrupt preemption.

It is required to omit the usage of frame pointers by adding the -fomit-frame-pointer option to your debug.mk or release.mk file:

    RISCV_ASFLAGS += -O0 -fomit-frame-pointer
    RISCV_CFLAGS += -O0 -fomit-frame-pointer
    RISCV_CXXFLAGS += -O0 -fomit-frame-pointer    

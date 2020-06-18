# Copyright 2019 SiFive, Inc #
# SPDX-License-Identifier: Apache-2.0 #

PROGRAM ?= clic-nested-interrupts-baremetal

# didn't work
#RISCV_CCASFLAGS += -fomit-frame-pointer
#CFLAGS += -fomit-frame-pointer
#RISCV_ASFLAGS += -fomit-frame-pointer
#RISCV_CFLAGS += -fomit-frame-pointer
#RISCV_CXXFLAGS += -fomit-frame-pointer
#reference:  CFLAGS="$(RISCV_CFLAGS)"

$(PROGRAM): $(wildcard *.c) $(wildcard *.h) $(wildcard *.S)

clean:
	rm -f $(PROGRAM) $(PROGRAM).hex


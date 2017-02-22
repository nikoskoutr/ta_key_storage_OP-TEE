CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

OBJS = main.o

CFLAGS += -Wall -I../ta/include -I$(TEEC_EXPORT)/include -I./include
#Add/link other required libraries here
LDADD += -L$(TEEC_EXPORT)/lib -lteec -L./lib/

BINARY=ta_key_storage

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) $(LDADD) -o $@ $<

.PHONY: clean
clean:
	rm -f $(OBJS) $(BINARY)

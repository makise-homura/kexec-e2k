PROG = kexec-lintel

.PHONY: all clean

all: $(PROG)

$(PROG): $(PROG).c
	gcc -I /usr/include/pci -lpci -o $@ $^

clean:
	rm -f $(PROG)

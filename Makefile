PROG = kexec-lintel

.PHONY: all clean

all: $(PROG)

$(PROG): $(PROG).c
	gcc -o $@ $^

clean:
	rm -f $(PROG)

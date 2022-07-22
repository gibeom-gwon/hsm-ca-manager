CFLAGS=-Wall -O2
LDLIBS=-lcrypto
TARGETS=gen_root_ca_cert
OBJS=gen_root_ca_cert.o

all: $(TARGETS)

gen_root_ca_cert: gen_root_ca_cert.o
	$(CC) -o $@ $^ $(LDLIBS)

clean:
	rm $(TARGETS) $(OBJS)

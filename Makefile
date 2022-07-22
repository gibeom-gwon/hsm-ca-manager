CFLAGS=-Wall -O2
LDLIBS=-lcrypto
TARGETS=gen_ca_cert
OBJS=gen_ca_cert.o

all: $(TARGETS)

gen_ca_cert: gen_ca_cert.o
	$(CC) -o $@ $^ $(LDLIBS)

clean:
	rm gen_ca_cert $(OBJS)

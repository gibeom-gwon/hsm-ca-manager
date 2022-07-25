CFLAGS=-Wall -O2
LDLIBS=-lcrypto
TARGETS=gen_root_ca_cert sign_csr
OBJS=gen_root_ca_cert.o sign_csr.o openssl.o

all: $(TARGETS)

gen_root_ca_cert: gen_root_ca_cert.o openssl.o
	$(CC) -o $@ $^ $(LDLIBS)

sign_csr: sign_csr.o openssl.o
	$(CC) -o $@ $^ $(LDLIBS)

clean:
	rm $(TARGETS) $(OBJS)

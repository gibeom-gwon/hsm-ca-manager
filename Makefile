CFLAGS=-Wall -O2
LDLIBS=-lcrypto
TARGETS=csr_sign

all: $(TARGETS)

csr_sign: csr_sign.o openssl.o cert.o cert_io.o cert_ext.o hsm.o ip.o
	$(CC) -o $@ $^ $(LDLIBS)

clean:
	rm $(TARGETS) *.o

CFLAGS=-Wall -O2
LDLIBS=-lcrypto
TARGETS=csr_sign csr_gen
OPENSSL_OBJ=openssl.o cert.o cert_io.o cert_ext.o hsm.o

all: $(TARGETS)

csr_sign: csr_sign.o $(OPENSSL_OBJ) ip.o pkcs11_uri.o hexstring.o
	$(CC) -o $@ $^ $(LDLIBS)

csr_gen: csr_gen.o $(OPENSSL_OBJ) ip.o pkcs11_uri.o hexstring.o
	$(CC) -o $@ $^ $(LDLIBS)

clean:
	rm $(TARGETS) *.o

P11KIT=p11-kit-1
CFLAGS=-Wall -O2 `pkg-config --cflags $(P11KIT)`
LDLIBS=-lcrypto
TARGETS=csr_sign csr_gen hsm_keygen
OPENSSL_OBJ=openssl.o cert.o cert_io.o cert_ext.o hsm.o

all: $(TARGETS)

csr_sign: csr_sign.o $(OPENSSL_OBJ) ip.o pkcs11_uri.o hexstring.o
	$(CC) -o $@ $^ $(LDLIBS)

csr_gen: csr_gen.o $(OPENSSL_OBJ) ip.o pkcs11_uri.o hexstring.o
	$(CC) -o $@ $^ $(LDLIBS)

hsm_keygen: hsm_keygen.o pkcs11_uri.o hexstring.o
	$(CC) -o $@ $^ `pkg-config --libs $(P11KIT)`

clean:
	rm $(TARGETS) *.o

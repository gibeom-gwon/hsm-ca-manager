CFLAGS=-Wall -O2
LDLIBS=-lcrypto
TARGETS=csr_sign
OBJS=csr_sign.o openssl.o

all: $(TARGETS)

csr_sign: csr_sign.o openssl.o
	$(CC) -o $@ $^ $(LDLIBS)

clean:
	rm $(TARGETS) *.o

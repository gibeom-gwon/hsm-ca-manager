CFLAGS=-Wall -O2
LDLIBS=-lcrypto
TARGETS=sign_csr
OBJS=sign_csr.o openssl.o

all: $(TARGETS)

sign_csr: sign_csr.o openssl.o
	$(CC) -o $@ $^ $(LDLIBS)

clean:
	rm $(TARGETS) $(OBJS)

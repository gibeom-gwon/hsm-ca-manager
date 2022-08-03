#include <openssl/pem.h>
#include "cert_io.h"

X509_REQ *load_csr(const char *filepath)
{
	X509_REQ *cert_req = NULL;
	FILE *csr_file = fopen(filepath,"rb");
	if(csr_file == NULL)
		return NULL;
	if(PEM_read_X509_REQ(csr_file,&cert_req,NULL,NULL) == NULL)
	{
		fclose(csr_file);
		return NULL;
	}
	fclose(csr_file);
	return cert_req;
}

X509 *load_x509(const char *filepath)
{
	X509 *cert = NULL;
	FILE *ca_cert_file = fopen(filepath,"rb");
	if(ca_cert_file == NULL)
		return NULL;
	if(PEM_read_X509(ca_cert_file,&cert,NULL,NULL) == NULL)
	{
		fclose(ca_cert_file);
		return NULL;
	}
	fclose(ca_cert_file);
	return cert;
}

int export_x509_to_der_file(const char *filepath, X509 *cert)
{
	FILE *f = fopen("root_ca.der","wb");
	if(!f)
		return 0;
	if(!i2d_X509_fp(f,cert))
	{
		fclose(f);
		return 0;
	}
	fclose(f);
	return 1;
}

int export_x509_to_pem_file(const char *filepath, X509 *cert)
{
	FILE *file = fopen(filepath,"wb");
	if(!file)
		return 0;
	if(!PEM_write_X509(file,cert))
	{
		fclose(file);
		return 0;
	}
	fclose(file);
	return 1;
}

int print_x509_pem(X509 *cert)
{
	return PEM_write_X509(stdout,cert);
}

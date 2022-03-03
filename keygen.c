/*
develop by Luis Alberto
Twitter: @albertobsd
email: alberto.bsd@gmail.com


Install dependencies: 

apt install libssl-dev
apt install libgcrypt20-dev
apt install libgmp-dev

Compilation:
gcc -o keygen keygen.c gmpecc.o util.o sha256.o base58.o rmd160.o -lgmp -lcrypto `libgcrypt-config --cflags --libs`
 
Usage Examples:	
./keygen -s openssl -b 250
./keygen -s urandom -b 256
./keygen -s random -b 64
./keygen -s getrandom
./keygen -s gcrypt -b 128


*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <openssl/rand.h>
#include <sys/random.h>
#include <gcrypt.h>

#include "util.h"

#include "gmpecc.h"
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "sha256/sha256.h"

struct Elliptic_Curve EC;
struct Point G;
struct Point DoublingG[256];

const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

void generate_publickey_address_rmd160(struct Point *publickey,bool compress,char *dst_publickey,char *dst_address,char *dst_rmd160);
void generate_publickey_and_address(struct Point *publickey,bool compress,char *dst_publickey,char *dst_address);

const char *sources[5] = {"urandom","random","openssl","getrandom","gcrypt"};

gmp_randstate_t state;

/*
for some reason the GMP function mp_set_memory_functions needs a extra parameter in the function call of realloc  and free warppers
*/
void *wrapper_gcry_alloc(size_t size);
void *wrapper_gcry_realloc(void *ptr, size_t old_size,  size_t new_size); 
void wrapper_gcry_free(void *ptr, size_t cur_size);


int main(int argc, char **argv)	{
	unsigned long err;
	int FLAG_SOURCE = 0,INDEX_SOURCE = 0,FLAG_BITS = 0;
	int bits = 256,maxbits;
	int bytes = 32,index,i,rc;
	char c,*buffer_key;
	FILE *fd;
	mpz_t key;
	struct Point publickey;
	char str_publickey[131];
	char str_address[50];
	char str_rmd[50];
	char *hextemp,*aux,*public_address;
	mp_set_memory_functions(wrapper_gcry_alloc,wrapper_gcry_realloc,wrapper_gcry_free);	//Using secure memory storage from lib gcrypt
	buffer_key = (char*)gcry_malloc_secure(32);	//Secure buffer for the KEY
		
	/* Init Constant Values in mpz numbers */
	mpz_init_set_str(EC.p, EC_constant_P, 16);
	mpz_init_set_str(EC.n, EC_constant_N, 16);
	mpz_init_set_str(G.x , EC_constant_Gx, 16);
	mpz_init_set_str(G.y , EC_constant_Gy, 16);
	init_doublingG(&G);
	
	/* Init empty values */
	mpz_init(publickey.x);
	mpz_init(publickey.y);
	mpz_init(key);
	
	gmp_randinit_mt(state);
	gmp_randseed_ui(state, ((int)clock()) + ((int)time(NULL)) );

	while ((c = getopt(argc, argv, "b:s:")) != -1) {
		switch(c)	{
			case 's':
				index = indexOf(optarg,sources,5);
				FLAG_SOURCE = 1;
				INDEX_SOURCE = index;
			break;
			case 'b':
				bits = strtol(optarg,NULL,10);
				if(bits >256 || bits < 1)	{
					bits = 256;
				}
				else	{
					bytes = bits / 8;
					if(bits % 8 != 0)	{
						bytes++;
					}
					FLAG_BITS = 1;
				}
			break;
		}
	}
	
	switch(INDEX_SOURCE)	{
		case -1:
			fprintf(stderr,"Invalid option: -s %s\n",optarg);
			exit(0);
		break;
		case 0:
			fd = fopen("/dev/urandom","rb");
			if(fd == NULL)	{
				fprintf(stderr,"Can't open /dev/urandom\n");
				exit(0);
			}
			fread(buffer_key,1,bytes,fd);
			fclose(fd);
			mpz_import(key,bytes,1,1,0,0,buffer_key);
		break;
		case 1:
			fd = fopen("/dev/random","rb");
			if(fd == NULL)	{
				fprintf(stderr,"Can't open /dev/random\n");
				exit(0);
			}
			fread(buffer_key,1,bytes,fd);
			fclose(fd);
			mpz_import(key,bytes,1,1,0,0,buffer_key);
		break;
		case 2:
			rc = RAND_bytes(buffer_key, bytes);
			if(rc != 1) {
				fprintf(stderr,"OpenSSL error: %l\n",err);
				exit(0);
			}
			mpz_import(key,bytes,1,1,0,0,buffer_key);
		break;
		case 3:
			getrandom(buffer_key,bytes,GRND_NONBLOCK);
			mpz_import(key,bytes,1,1,0,0,buffer_key);
		break;
		case 4:
			gcry_randomize(buffer_key,bytes,GCRY_VERY_STRONG_RANDOM);			
			mpz_import(key,bytes,1,1,0,0,buffer_key);
		break;
	}
	
	if(FLAG_BITS)	{
		maxbits = mpz_sizeinbase(key,2);
		
		if(maxbits > bits)	{	// If the number of maxbis is great that the bit size requested we need to clear those upper bits
			for(i = maxbits ; i > bits; i--)	{
				mpz_clrbit(key,i-1);
			}
			
		}
		mpz_setbit(key,bits-1); // In any case we need to set the requested bit in 1 to fit the Key to the specific subrange.
	}
	Scalar_Multiplication(G,&publickey,key);
	
	gmp_printf("KEY (Secret: DON'T SHARE THIS VALUE): %Zx\n",key);

	//void generate_publickey_and_address(struct Point *publickey,bool compress,char *dst_publickey,char *dst_address)
	generate_publickey_and_address(&publickey,false,str_publickey,str_address);

	printf("publickey uncompressed: %s\n",str_publickey);
	printf("address uncompressed %s\n",str_address);
	
	generate_publickey_and_address(&publickey,true,str_publickey,str_address);
	printf("publickey compressed: %s\n",str_publickey);
	printf("address compressed %s\n",str_address);

	//We overwrite the random buffer and the key mpz
	for(i = 0; i <256;i++){
		mpz_urandomb(key,state,256);
		memset(buffer_key,i,32);	
	}
	mpz_clear(key);
	gcry_free(buffer_key);
	return 0;
}

void generate_publickey_address_rmd160(struct Point *publickey,bool compress,char *dst_publickey,char *dst_address,char *dst_rmd160)	{
	char bin_publickey[65];
	char bin_sha256[32];
	char bin_digest[60];
	size_t pubaddress_size = 50;
	memset(dst_address,0,50);
	memset(dst_publickey,0,131);
	if(compress)	{
		if(mpz_tstbit(publickey->y, 0) == 0)	{	// Even
			gmp_snprintf (dst_publickey,67,"02%0.64Zx",publickey->x);
		}
		else	{
			gmp_snprintf(dst_publickey,67,"03%0.64Zx",publickey->x);
		}
		hexs2bin(dst_publickey,bin_publickey);
		sha256(bin_publickey, 33, bin_sha256);
	}
	else	{
		gmp_snprintf(dst_publickey,131,"04%0.64Zx%0.64Zx",publickey->x,publickey->y);
		hexs2bin(dst_publickey,bin_publickey);
		sha256(bin_publickey, 65, bin_sha256);
	}
	RMD160Data((const unsigned char*)bin_sha256,32, bin_digest+1);
	
	tohex_dst(bin_digest+1,20,dst_rmd160);
	
	/* Firts byte 0, this is for the Address begining with 1.... */
	
	bin_digest[0] = 0;
	
	/* Double sha256 checksum */	
	sha256(bin_digest, 21, bin_digest+21);
	sha256(bin_digest+21, 32, bin_digest+21);
	
	/* Get the address */
	if(!b58enc(dst_address,&pubaddress_size,bin_digest,25)){
		fprintf(stderr,"error b58enc\n");
	}	
}


void generate_publickey_and_address(struct Point *publickey,bool compress,char *dst_publickey,char *dst_address)	{
	char bin_publickey[65];
	char bin_sha256[32];
	char bin_digest[60];
	size_t pubaddress_size = 50;
	memset(dst_address,0,50);
	memset(dst_publickey,0,131);
	if(compress)	{
		if(mpz_tstbit(publickey->y, 0) == 0)	{	// Even
			gmp_snprintf (dst_publickey,67,"02%0.64Zx",publickey->x);
		}
		else	{
			gmp_snprintf(dst_publickey,67,"03%0.64Zx",publickey->x);
		}
		hexs2bin(dst_publickey,bin_publickey);
		sha256(bin_publickey, 33, bin_sha256);
	}
	else	{
		gmp_snprintf(dst_publickey,131,"04%0.64Zx%0.64Zx",publickey->x,publickey->y);
		hexs2bin(dst_publickey,bin_publickey);
		sha256(bin_publickey, 65, bin_sha256);
	}
	RMD160Data((const unsigned char*)bin_sha256,32, bin_digest+1);
	
	/* Firts byte 0, this is for the Address begining with 1.... */
	
	bin_digest[0] = 0;
	
	/* Double sha256 checksum */	
	sha256(bin_digest, 21, bin_digest+21);
	sha256(bin_digest+21, 32, bin_digest+21);
	
	/* Get the address */
	if(!b58enc(dst_address,&pubaddress_size,bin_digest,25)){
		fprintf(stderr,"error b58enc\n");
	}
}

void *wrapper_gcry_alloc(size_t size)	{	//To use calloc instead of malloc
	return gcry_calloc(size,1);
}

void *wrapper_gcry_realloc(void *ptr, size_t old_size,  size_t new_size)	{
	return gcry_realloc(ptr,new_size);
}

void wrapper_gcry_free(void *ptr, size_t cur_size)	{
	gcry_free(ptr);
}
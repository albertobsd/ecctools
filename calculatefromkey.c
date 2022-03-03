/*
	develop by Luis Alberto
	Twitter: @albertobsd
	email: alberto.bsd@gmail.com
	

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

void generate_publickey_and_address(struct Point *publickey,bool compress,char *dst_publickey,char *dst_address);
/*
for some reason the GMP function mp_set_memory_functions needs a extra parameter in the function call of realloc  and free warppers
*/
void *wrapper_gcry_alloc(size_t size);
void *wrapper_gcry_realloc(void *ptr, size_t old_size,  size_t new_size); 
void wrapper_gcry_free(void *ptr, size_t cur_size);

int main(int argc, char **argv)	{
	mpz_t key;
	struct Point publickey;
	char value[65];
	char str_publickey[131];
	char str_address[50];
	char *hextemp,*aux,*public_address;
	
	mp_set_memory_functions(wrapper_gcry_alloc,wrapper_gcry_realloc,wrapper_gcry_free);	//Using secure memory storage from lib gcrypt
	
	mpz_init_set_str(EC.p, EC_constant_P, 16);
	mpz_init_set_str(EC.n, EC_constant_N, 16);
	mpz_init_set_str(G.x , EC_constant_Gx, 16);
	mpz_init_set_str(G.y , EC_constant_Gy, 16);
	init_doublingG(&G);
	
	mpz_init(publickey.x);
	mpz_init(publickey.y);
	mpz_init(key);
	
	if(argc != 2)	{
		exit(0);
	}
	
	mpz_set_str(key,argv[1],16);
	Scalar_Multiplication(G,&publickey,key);
	
	gmp_printf("privatekey: %0.64Zx\n",key);
	
	generate_publickey_and_address(&publickey,true,str_publickey,str_address);
	printf("publickey compressed: %s\n",str_publickey);
	printf("public address compressed %s\n",str_address);

	generate_publickey_and_address(&publickey,false,str_publickey,str_address);
	printf("publickey uncompressed: %s\n",str_publickey);
	printf("public address uncompressed %s\n",str_address);
	
	return 0;
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
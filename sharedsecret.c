/*
develop by Luis Alberto
Twitter: @albertobsd
email: alberto.bsd@gmail.com

Compilation:
gcc -o sharedsecret sharedsecret.c gmpecc.o util.o sha256.o base58.o rmd160.o -lgmp


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

#include "util.h"

#include "gmpecc.h"
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "sha256/sha256.h"

const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";


void set_publickey(char *param);
void Scalar_Multiplication_custom(struct Point P, struct Point *R, mpz_t m);

struct Point target_publickey,publickey;

int main(int argc, char **argv)	{
	char buffer[1024];
	mpz_t key;

	char *hextemp,*aux,*public_address;
		
	/* Init Constant Values in mpz numbers */
	mpz_init_set_str(EC.p, EC_constant_P, 16);
	mpz_init_set_str(EC.n, EC_constant_N, 16);
	mpz_init_set_str(G.x , EC_constant_Gx, 16);
	mpz_init_set_str(G.y , EC_constant_Gy, 16);
	init_doublingG(&G);
	
	
	/* Init empty values */
	mpz_init(target_publickey.x);
	mpz_init(target_publickey.y);
	mpz_init(publickey.x);
	mpz_init(publickey.y);

	mpz_init(key);
	printf("A: private key (hex): ");
	fgets(buffer,1022,stdin);
	trim(buffer," \n\r\t");
	mpz_set_str(key,buffer,16);
	if(mpz_cmp_ui(key,0) == 0 )	{
		fprintf(stderr,"The key can't zero\n");
		exit(0);
	}
	printf("B: public key : ");
	fgets(buffer,1022,stdin);	
	trim(buffer," \n\r\t");
	set_publickey(buffer);
	if(mpz_cmp_ui(target_publickey.x,0) == 0 || mpz_cmp_ui(target_publickey.y,0) == 0 )	{
		fprintf(stderr,"The public key is invalid\n");
		exit(0);
	}
	Scalar_Multiplication_custom(target_publickey, &publickey,key);
	gmp_printf("Secret between A and B: %Zx (DON'T SHARE, THIS IS SECRET)\n",publickey.x);
	return 0;
}

void set_publickey(char *param)	{
	mpz_t mpz_aux,mpz_aux2,Ysquared;
	char hexvalue[65];
	char *dest;
	int len;
	len = strlen(param);
	dest = (char*) calloc(len+1,1);
	
	if(dest == NULL)	{
		fprintf(stderr,"[E] Error calloc\n");
		exit(0);
	}
	memset(hexvalue,0,65);
	memcpy(dest,param,len);
	trim(dest," \t\n\r");
	len = strlen(dest);
	switch(len)	{
		case 66:
			mpz_set_str(target_publickey.x,dest+2,16);
		break;
		case 130:
			memcpy(hexvalue,dest+2,64);
			mpz_set_str(target_publickey.x,hexvalue,16);
			memcpy(hexvalue,dest+66,64);
			mpz_set_str(target_publickey.y,hexvalue,16);
		break;
		default:
			fprintf(stderr,"Invalid Publickey\n");
			exit(0);
		break;
	}
	if(mpz_cmp_ui(target_publickey.y,0) == 0)	{
		mpz_init(mpz_aux);
		mpz_init(mpz_aux2);
		mpz_init(Ysquared);
		mpz_pow_ui(mpz_aux,target_publickey.x,3);
		mpz_add_ui(mpz_aux2,mpz_aux,7);
		mpz_mod(Ysquared,mpz_aux2,EC.p);
		mpz_add_ui(mpz_aux,EC.p,1);
		mpz_fdiv_q_ui(mpz_aux2,mpz_aux,4);
		mpz_powm(target_publickey.y,Ysquared,mpz_aux2,EC.p);
		mpz_sub(mpz_aux, EC.p,target_publickey.y);
		switch(dest[1])	{
			case '2':
				if(mpz_tstbit(target_publickey.y, 0) == 1)	{
					mpz_set(target_publickey.y,mpz_aux);
				}
			break;
			case '3':
				if(mpz_tstbit(target_publickey.y, 0) == 0)	{
					mpz_set(target_publickey.y,mpz_aux);
				}
			break;
			default:
				fprintf(stderr,"[E] Some invalid bit in the publickey: %s\n",dest);
				exit(0);
			break;
		}
		mpz_clear(mpz_aux);
		mpz_clear(mpz_aux2);
		mpz_clear(Ysquared);
	}
	free(dest);
}

void Scalar_Multiplication_custom(struct Point P, struct Point *R, mpz_t m)  {
	struct Point Q, T;
	long no_of_bits, loop;
	mpz_init(Q.x);
	mpz_init(Q.y);
	mpz_init(T.x);
	mpz_init(T.y);
	no_of_bits = mpz_sizeinbase(m, 2);
	mpz_set_ui(R->x, 0);
	mpz_set_ui(R->y, 0);
	if(mpz_cmp_ui(m, 0) != 0)  {
  	mpz_set(Q.x, P.x);
  	mpz_set(Q.y, P.y);
  	if(mpz_tstbit(m, 0) == 1){
  		mpz_set(R->x, P.x);
  		mpz_set(R->y, P.y);
  	}
  	for(loop = 1; loop < no_of_bits; loop++) {
  		Point_Doubling(&Q, &T);
  		mpz_set(Q.x, T.x);
  		mpz_set(Q.y, T.y);
  		mpz_set(T.x, R->x);
  		mpz_set(T.y, R->y);
  		if(mpz_tstbit(m, loop))
  			Point_Addition(&T, &Q, R);
  	}
  }
	mpz_clear(Q.x);
  mpz_clear(Q.y);
	mpz_clear(T.x);
  mpz_clear(T.y);
}
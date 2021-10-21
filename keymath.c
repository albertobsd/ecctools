/*
Developed by Luis Alberto
email: alberto.bsd@gmail.com
gcc -o keymath keymath.c -lgmp
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


const char *version = "0.1.211009";
const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";


const char *formats[3] = {"publickey","rmd160","address"};
const char *looks[2] = {"compress","uncompress"};

void set_publickey(char *param,struct Point *publickey);
void generate_strpublickey(struct Point *publickey,bool compress,char *dst);
void Scalar_Multiplication_custom(struct Point P, struct Point *R, mpz_t m);

char *str_output = NULL;
char *str_input = NULL;
char *str_publickey_ptr = NULL;

char str_publickey[132];
char str_rmd160[41];
char str_address[41];

struct Point A,B,C;

int FLAG_NUMBER = 0;

mpz_t inversemultiplier,number;

int main(int argc, char **argv)  {
	char buffer_input[1024];
	mpz_init_set_str(EC.p, EC_constant_P, 16);
	mpz_init_set_str(EC.n, EC_constant_N, 16);
	mpz_init_set_str(G.x , EC_constant_Gx, 16);
	mpz_init_set_str(G.y , EC_constant_Gy, 16);
	init_doublingG(&G);


	mpz_init_set_ui(A.x,0);
	mpz_init_set_ui(A.y,0);

	mpz_init_set_ui(B.x,0);
	mpz_init_set_ui(B.y,0);

	mpz_init_set_ui(C.x,0);
	mpz_init_set_ui(C.y,0);
	
	mpz_init(number);
	mpz_init(inversemultiplier);
	
	if(argc < 4)	{
		printf("Missing parameters\n");
		exit(0);
	}
	
	switch(strlen(argv[1]))	{
		case 66:
		case 130:
			set_publickey(argv[1],&A);
		break;
		default:
			printf("unknow publickey length\n");
			exit(0);
		break;
	}
	switch(strlen(argv[3]))	{
		case 66:
		case 130:
			set_publickey(argv[3],&B);
			FLAG_NUMBER = 0;
		break;
		default:
			mpz_set_str(number,argv[3],0);
			FLAG_NUMBER = 1;
		break;
	}
	switch(argv[2][0])	{
		case '+':
			if(FLAG_NUMBER)	{
				Scalar_Multiplication(G,&B,number);
			}
			Point_Addition(&A,&B,&C);
		
		break;
		case '-':
			if(FLAG_NUMBER)	{
				Scalar_Multiplication(G,&B,number);
			}
			Point_Negation(&B,&C);
			mpz_set(B.x,C.x);
			mpz_set(B.y,C.y);
			Point_Addition(&A,&B,&C);
		break;
		case '/':
			if(!FLAG_NUMBER)	{
				printf("We don't know how to divide 2 publickeys, we need an escalar number\n");
				exit(0);
			}
			else	{
				mpz_invert(inversemultiplier,number,EC.n);
				Scalar_Multiplication_custom(A,&C,inversemultiplier);
			}
		break;
		case 'x':
			if(!FLAG_NUMBER)	{
				printf("We don't know how to multiply 2 publickeys, we need an escalar number\n");
				exit(0);
			}
			else	{
				Scalar_Multiplication_custom(A,&C,number);
			}
		break;		
	}
	generate_strpublickey(&C,true,str_publickey);
	printf("Result: %s\n\n",str_publickey);	
}

void generate_strpublickey(struct Point *publickey,bool compress,char *dst)	{
	memset(dst,0,131);
	if(compress)	{
		if(mpz_tstbit(publickey->y, 0) == 0)	{	// Even
			gmp_snprintf (dst,67,"02%0.64Zx",publickey->x);
		}
		else	{
			gmp_snprintf(dst,67,"03%0.64Zx",publickey->x);
		}
	}
	else	{
		gmp_snprintf(dst,131,"04%0.64Zx%0.64Zx",publickey->x,publickey->y);
	}
}

void set_publickey(char *param,struct Point *publickey)	{
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
			mpz_set_str(publickey->x,dest+2,16);
		break;
		case 130:
			memcpy(hexvalue,dest+2,64);
			mpz_set_str(publickey->x,hexvalue,16);
			memcpy(hexvalue,dest+66,64);
			mpz_set_str(publickey->y,hexvalue,16);
		break;
	}
	if(mpz_cmp_ui(publickey->y,0) == 0)	{
		mpz_t mpz_aux,mpz_aux2,Ysquared;
		mpz_init(mpz_aux);
		mpz_init(mpz_aux2);
		mpz_init(Ysquared);
		mpz_pow_ui(mpz_aux,publickey->x,3);
		mpz_add_ui(mpz_aux2,mpz_aux,7);
		mpz_mod(Ysquared,mpz_aux2,EC.p);
		mpz_add_ui(mpz_aux,EC.p,1);
		mpz_fdiv_q_ui(mpz_aux2,mpz_aux,4);
		mpz_powm(publickey->y,Ysquared,mpz_aux2,EC.p);
		mpz_sub(mpz_aux, EC.p,publickey->y);
		switch(dest[1])	{
			case '2':
				if(mpz_tstbit(publickey->y, 0) == 1)	{
					mpz_set(publickey->y,mpz_aux);
				}
			break;
			case '3':
				if(mpz_tstbit(publickey->y, 0) == 0)	{
					mpz_set(publickey->y,mpz_aux);
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
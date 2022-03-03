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


struct Elliptic_Curve EC;
struct Point G;
struct Point DoublingG[256];

const char *version = "0.1.211009";
const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

char *str_output = NULL;
char *str_input = NULL;
char *str_publickey_ptr = NULL;

char str_publickey[132];
char str_rmd160[41];
char str_address[41];

mpz_t A,B,C;

int FLAG_NUMBER = 0;

mpz_t inversemultiplier,number;

int main(int argc, char **argv)  {
	char buffer_input[1024];
	mpz_init_set_str(EC.p, EC_constant_P, 16);
	mpz_init_set_str(EC.n, EC_constant_N, 16);
	mpz_init_set_str(G.x , EC_constant_Gx, 16);
	mpz_init_set_str(G.y , EC_constant_Gy, 16);

	mpz_init_set_ui(A,0);
	mpz_init_set_ui(B,0);
	mpz_init_set_ui(C,0);
	
	mpz_init(number);
	mpz_init(inversemultiplier);
	
	if(argc < 4)	{
		printf("Missing parameters\n");
		exit(0);
	}
	
	
	mpz_set_str(A,argv[1],0);
	mpz_set_str(B,argv[3],0);
	
	switch(argv[2][0])	{
		case '+':
			mpz_add(C,A,B);	
			mpz_mod(C,C,EC.n);
		break;
		case '-':
			mpz_sub(C,A,B);
			mpz_mod(C,C,EC.n);
		break;
		case '/':
			mpz_invert(inversemultiplier,B,EC.n);
			mpz_mul(C,A,inversemultiplier);
			mpz_mod(C,C,EC.n);
		break;
		case 'x':
			mpz_mul(C,A,B);
			mpz_mod(C,C,EC.n);
		break;		
	}
	gmp_printf("Result: %Zx\n\n",C);	
}

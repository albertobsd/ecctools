/*
Developed by Luis Alberto
email: alberto.bsd@gmail.com
gcc -o keydivision keydivision.c -lgmp
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

void showhelp();
void set_format(char *param);
void set_look(char *param);
void set_publickey(char *param);
void set_divisor(char *param);
void generate_straddress(struct Point *publickey,bool compress,char *dst);
void generate_strrmd160(struct Point *publickey,bool compress,char *dst);
void generate_strpublickey(struct Point *publickey,bool compress,char *dst);

void Scalar_Multiplication_custom(struct Point P, struct Point *R, mpz_t m);

char *str_output = NULL;
char *str_input = NULL;
char *str_publickey_ptr = NULL;

char str_publickey[132];
char str_rmd160[41];
char str_address[41];

struct Point target_publickey,dst_publickey,temp_point;

int FLAG_PUBLIC = 0;
int FLAG_FORMART = 0;
int FLAG_HIDECOMMENT = 0;
int FLAG_LOOK = 0;
int FLAG_MODE = 0;
int FLAG_N;
int FLAG_DIVISOR = 0;
int FLAG_PUBLIC_FILE = 0;
int N = 1,M;

mpz_t divisor,inversemultiplier,base_key,sum_key,dst_key;
gmp_randstate_t state;

int main(int argc, char **argv)  {
	char buffer_input[1024];
	char *temp;
	FILE *OUTPUT,*INPUT;
	char c;
	int i = 0,entrar;
	mpz_init_set_str(EC.p, EC_constant_P, 16);
	mpz_init_set_str(EC.n, EC_constant_N, 16);
	mpz_init_set_str(G.x , EC_constant_Gx, 16);
	mpz_init_set_str(G.y , EC_constant_Gy, 16);
	init_doublingG(&G);


	mpz_init_set_ui(target_publickey.x,0);
	mpz_init_set_ui(target_publickey.y,0);

	mpz_init_set_ui(dst_publickey.x,0);
	mpz_init_set_ui(dst_publickey.y,0);

	mpz_init_set_ui(temp_point.x,0);
	mpz_init_set_ui(temp_point.y,0);
	
	
	
	while ((c = getopt(argc, argv, "hvxRd:n:i:o:p:r:f:l:")) != -1) {
		switch(c) {
			case 'd':
				set_divisor((char *)optarg);
			break;
			case 'x':
				FLAG_HIDECOMMENT = 1;
			break;
			case 'h':
				showhelp();
				exit(0);
			break;
			case 'n':
				N = strtol((char *)optarg,NULL,10);
				if(N<= 0)	{
					fprintf(stderr,"[E] invalid bit N number %s, setting default N = 1\n",optarg);
					N = 1;
				}
				
				FLAG_N = 1;
			break;
			case 'o':
				str_output = (char *)optarg;
			break;
			case 'i':
				FLAG_PUBLIC_FILE = 1;
				str_input = (char *)optarg;
			break;
			case 'p':
				str_publickey_ptr = optarg;
				FLAG_PUBLIC = 1;
			break;
			case 'v':
				printf("version %s\n",version);
				exit(0);
			break;
			case 'l':
				set_look((char *)optarg);
			break;
			case 'f':
				set_format((char *)optarg);
			break;
		}
	}
	
	if(FLAG_DIVISOR == 0 )	{
		mpz_init_set_ui(divisor,2);
	}
	mpz_init(inversemultiplier);
	mpz_invert(inversemultiplier,divisor,EC.n);
	gmp_printf("inversemultiplier : %Zx\n",inversemultiplier);
	if(str_output)	{
		OUTPUT = fopen(str_output,"a");
		if(OUTPUT == NULL)	{
			fprintf(stderr,"can't opent file %s\n",str_output);
			OUTPUT = stdout;
		}
	}
	else	{
		OUTPUT = stdout;
	}
	
	if( (FLAG_PUBLIC || FLAG_PUBLIC_FILE))	{
		if(FLAG_PUBLIC_FILE){
			INPUT = fopen(str_input,"r");
			if(INPUT == NULL)	{
				fprintf(stderr,"Can't open the file %s\n",str_input);
				exit(0);
			}
		}
		entrar = 1;
		while(entrar)	{
			if(FLAG_PUBLIC){
				set_publickey(str_publickey_ptr);
			}
			else	{
				temp = fgets(buffer_input,1024,INPUT);
				if(temp != buffer_input)	{
					exit(0);
				}
				trim(buffer_input," \r\n\t");
				set_publickey(buffer_input);
			}
			
			mpz_set(temp_point.x,target_publickey.x);
			mpz_set(temp_point.y,target_publickey.y);
			i = 0;
			while( i < N)	{
				/* Magic occurs here */
				
				Scalar_Multiplication_custom(temp_point, &dst_publickey,inversemultiplier);		/*Here is the "division" in ECC a  division is multiplation by the inverse of the divisor */
				switch(FLAG_FORMART)	{
					case 0: //Publickey
						generate_strpublickey(&dst_publickey,FLAG_LOOK == 0,str_publickey);
						fprintf(OUTPUT,"%s\n",str_publickey);
					break;
					case 1: //rmd160
						generate_strrmd160(&dst_publickey,FLAG_LOOK == 0,str_rmd160);
						fprintf(OUTPUT,"%s\n",str_rmd160);
					break;
					case 2:	//address
						generate_straddress(&target_publickey,FLAG_LOOK == 0,str_address);
						fprintf(OUTPUT,"%s\n",str_address);
					
					break;					
					
				}
							
				mpz_set(temp_point.x,dst_publickey.x);
				mpz_set(temp_point.y,dst_publickey.y);

				i++;
			}
			
			if(FLAG_PUBLIC){
				entrar = 0;
			}
			else	{
				if(feof(INPUT)){
					entrar = 0;
				}
			}
		}
	}
	else	{
		fprintf(stderr,"Version: %s\n",version);
		fprintf(stderr,"[E] there are some missing parameter\n");
		showhelp();
	}
	
	/* Why we clean the variables if we are going to quit? */
	mpz_clear(dst_publickey.x);
	mpz_clear(dst_publickey.y);
	mpz_clear(base_key);
	mpz_clear(sum_key);
	return 0;
}

void showhelp()	{
	printf("\nUsage:\n-h\t\tshow this help\n");
	printf("-d num\tNumber divisor\n");
	printf("-f format\tOutput format <publickey, rmd160, address>. Default: publickey\n");
	printf("-l look\t\tOutput <compress, uncompress>. Default: compress\n");
	printf("-n num\tNumber of consecutive divisions. Default 1\n");
	printf("-i file\t\tInput file, input file with public keys to be divided");
	printf("-o file\t\tOutput file, if you omit this option the out will go to the standar output\n");
	printf("-p key\t\tPublickey to be substracted compress or uncompress\n");
	printf("Developed by albertobsd\n\n");
}

void set_publickey(char *param)	{
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
	}
	if(mpz_cmp_ui(target_publickey.y,0) == 0)	{
		mpz_t mpz_aux,mpz_aux2,Ysquared;
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



void set_format(char *param)	{
	int index = indexOf(param,formats,3);
	if(index == -1)	{
		fprintf(stderr,"[E] Unknow format: %s\n",param);
	}
	else	{
		FLAG_FORMART = index;
	}
}

void set_look(char *param)	{
	int index = indexOf(param,looks,2);
	if(index == -1)	{
		fprintf(stderr,"[E] Unknow look: %s\n",param);
	}
	else	{
		FLAG_LOOK = index;
	}
}

void set_divisor(char *param)	{
	if(param[0] == '0' && param[0] == 'x'){
		mpz_init_set_str(divisor,param,16);
	}
	else	{
		mpz_init_set_str(divisor,param,16);
	}
	FLAG_DIVISOR = 1;
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

void generate_strrmd160(struct Point *publickey,bool compress,char *dst)	{
	char str_publickey[131];
	char bin_publickey[65];
	char bin_sha256[32];
	char bin_rmd160[20];
	memset(dst,0,42);
	if(compress)	{
		if(mpz_tstbit(publickey->y, 0) == 0)	{	// Even
			gmp_snprintf (str_publickey,67,"02%0.64Zx",publickey->x);
		}
		else	{
			gmp_snprintf(str_publickey,67,"03%0.64Zx",publickey->x);
		}
		hexs2bin(str_publickey,bin_publickey);
		sha256(bin_publickey, 33, bin_sha256);
	}
	else	{
		gmp_snprintf(str_publickey,131,"04%0.64Zx%0.64Zx",publickey->x,publickey->y);
		hexs2bin(str_publickey,bin_publickey);
		sha256(bin_publickey, 65, bin_sha256);
	}
	RMD160Data((const unsigned char*)bin_sha256,32, bin_rmd160);
	tohex_dst(bin_rmd160,20,dst);
}

void generate_straddress(struct Point *publickey,bool compress,char *dst)	{
	char str_publickey[131];
	char bin_publickey[65];
	char bin_sha256[32];
	char bin_digest[60];
	size_t pubaddress_size = 42;
	memset(dst,0,42);
	if(compress)	{
		if(mpz_tstbit(publickey->y, 0) == 0)	{	// Even
			gmp_snprintf (str_publickey,67,"02%0.64Zx",publickey->x);
		}
		else	{
			gmp_snprintf(str_publickey,67,"03%0.64Zx",publickey->x);
		}
		hexs2bin(str_publickey,bin_publickey);
		sha256(bin_publickey, 33, bin_sha256);
	}
	else	{
		gmp_snprintf(str_publickey,131,"04%0.64Zx%0.64Zx",publickey->x,publickey->y);
		hexs2bin(str_publickey,bin_publickey);
		sha256(bin_publickey, 65, bin_sha256);
	}
	RMD160Data((const unsigned char*)bin_sha256,32, bin_digest+1);
	
	/* Firts byte 0, this is for the Address begining with 1.... */
	
	bin_digest[0] = 0;
	
	/* Double sha256 checksum */	
	sha256(bin_digest, 21, bin_digest+21);
	sha256(bin_digest+21, 32, bin_digest+21);
	
	/* Get the address */
	if(!b58enc(dst,&pubaddress_size,bin_digest,25)){
		fprintf(stderr,"error b58enc\n");
	}
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
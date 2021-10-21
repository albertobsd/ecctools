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
#include "util.h"

#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "sha256/sha256.h"



void generate_address_from_publickey(char *publickey,char *dst_address);

int main(int argc, char **argv)	{
	char str_publickey[131];
	char str_address[50];
	char *hextemp,*aux,*public_address;
	
	/*If there is no a paramenter*/
	if(argc != 2)	{
		exit(0);
	}
	
	generate_address_from_publickey(argv[1],str_address);
	printf("address %s\n",str_address);
	
	return 0;
}

void generate_address_from_publickey(char *publickey,char *dst_address)	{
	char bin_publickey[65];
	char bin_sha256[32];
	char bin_digest[60];
	int len_publickey = strlen(publickey);
	size_t pubaddress_size = 50;
	memset(dst_address,0,50);
	
	hexs2bin(publickey,bin_publickey);
	switch(len_publickey)	{
		case 130:
			sha256(bin_publickey, 65, bin_sha256);
		break;
		case 66:
			sha256(bin_publickey, 33, bin_sha256);
		break;
		default:
			fprintf(stderr,"Incorrect length.\n");
			exit(0);
		break;
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
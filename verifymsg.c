/*
	gcc -O3 -o verifymsg verifymsg.c gmpecc.c util.o sha256.o base58.o rmd160.o -lgmp
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
#include <sys/random.h>
#include "util.h"

#include "gmpecc.h"
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "sha256/sha256.h"

#define SHA256_DIGEST_SIZE 32

bool VERBOSE = false;

struct Elliptic_Curve EC;
struct Point G;
struct Point DoublingG[256];

const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";


static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};

static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};


void build_decoding_table();
char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length);
unsigned char *base64_decode(const char *data, size_t input_length,size_t *output_length);
							 
void generate_strpublickey(struct Point *publickey,bool compress,char *dst);
void generate_straddress(struct Point *publickey,bool compress,char *dst);
void double_sha256(uint8_t *input, size_t length, uint8_t *digest);

void getYfromX(mpz_t x,mpz_t *y);
char *sign_message_b64(char *wifPrivateKey, char *message);

void msg_magic_hash(char *message,char *dst_digest);
char *msg_magic(char *message, int *len_output);
char *msg_bytes(char *message, int *len_output);
char *sign_message_with_private_key(char *base58_priv_key,char *message,bool compressed);
char *sign_and_verify(char *wifPrivateKey, char *message, char *bitcoinaddress, bool compressed);
char *sign_message_with_secret(mpz_t key,char *message, bool compressed);
void Scalar_Multiplication_custom(struct Point P, struct Point *R, mpz_t m);
bool verify_message(char *address,char *signature,char *message);

void print_signature(char *message,char *address, char *signature_base64);

int main(int argc,char **argv)	{
	bool flag_address = false,flag_message = false,flag_signature = false;
	char *address = NULL;
	char *message = NULL;
	char *signature = NULL;
	char *decoded;
	size_t output_length;
	char opt;
	mpz_init_set_str(EC.p, EC_constant_P, 16);
	mpz_init_set_str(EC.n, EC_constant_N, 16);
	mpz_init_set_str(G.x , EC_constant_Gx, 16);
	mpz_init_set_str(G.y , EC_constant_Gy, 16);
	init_doublingG(&G);

	while ((opt = getopt(argc, argv, "va:m:s:")) != -1) {
		switch (opt) {
			case 'a':
				address = optarg;
				flag_address = true;
			break;
			case 'm':
				message = optarg;
				flag_message =true;
			break;
			case 's':
				signature = optarg;
				flag_signature = true;
			break;
			case 'v':
				VERBOSE = true;
			break;
		}
	}
	if(!(flag_address && flag_message && flag_signature)){
		printf("Missing parameters\n");
		exit(0);
	}
	decoded = (char *)base64_decode(signature,strlen(signature),&output_length);
	if(verify_message(address,decoded,message))	{
		printf("\nThe signature match with the address and it is valid\n\n");
		print_signature(message,address,signature);
	}else	{
		printf("The signature is NOT valid\n");
	}
}

char *sign_message_with_private_key(char *base58_priv_key,char *message,bool compressed)	{
	char *signature;
	if(base58_priv_key == NULL || message == NULL)	{
		return NULL;
	}
	size_t len_base58_priv_key = strlen(base58_priv_key);
	
	if(!(len_base58_priv_key == 51 || len_base58_priv_key == 52)){
		if (VERBOSE) printf("len_base58_priv_key distinct of 51 or 52: current value: %li\n",len_base58_priv_key);
		return NULL;
	}
	if(!(base58_priv_key[0] == 'L' || base58_priv_key[0] == 'K' || base58_priv_key[0] == '5')){
		if (VERBOSE) printf("First letter distinc of L,K or 5. Current value %s\n",base58_priv_key);
		return NULL;
	}
	if ( !(((base58_priv_key[0] == 'L' || base58_priv_key[0] == 'K') && compressed) ||
		(base58_priv_key[0] == '5' && !compressed)) ) {
		if (VERBOSE) printf("First letter doesn't match with compressed flag (%s) \
		: but key is %s\n",compressed ? "compress":"uncompress",base58_priv_key);
		return NULL;
	}
		//
	mpz_t secret;
	int offset_checksum;
	size_t len_encoded_priv_key_bytes = compressed ? 38 : 37;
	char digest[SHA256_DIGEST_SIZE];
	char encoded_priv_key_bytes[39] = {0};
	char hex_priv_key[65] = {0};
	b58tobin(encoded_priv_key_bytes,&len_encoded_priv_key_bytes,base58_priv_key,len_base58_priv_key);
	if(compressed)
		offset_checksum = 34;
	else
		offset_checksum = 33;

	double_sha256(encoded_priv_key_bytes,offset_checksum,digest);
	if(memcmp(digest,encoded_priv_key_bytes+offset_checksum,4) != 0)	{
		if (VERBOSE) printf("WIF checksum missmatch\n");
		return NULL;
	}
	tohex_dst(encoded_priv_key_bytes+1,SHA256_DIGEST_SIZE,hex_priv_key);

	memset(digest,0,sizeof(digest));
	memset(encoded_priv_key_bytes,0,sizeof(encoded_priv_key_bytes));
	
	mpz_init_set_str(secret,hex_priv_key,16);
	memset(hex_priv_key,0,sizeof(hex_priv_key));
	signature = sign_message_with_secret(secret,message,compressed);
	
	mpz_set_ui(secret,0);
	mpz_clear(secret);
	return signature;
}

int mpz_geturandom(mpz_t *value,int bytes)	{
	size_t r;
	char raw_value[bytes],hex_value[65];
	r = getrandom(raw_value,bytes,GRND_NONBLOCK);
	if(r == -1)
		return 0;
	tohex_dst(raw_value,r,hex_value);
	mpz_set_str(*value,hex_value,16);
	memset(hex_value,0,sizeof(hex_value));
	memset(raw_value,0,sizeof(raw_value));
	return (int)r;
}

char *sign_message_with_secret(mpz_t key,char *message, bool compressed)	{
	mpz_t k,r,s,z,k_inv;
	struct Point publickey,R;
	char raw_z[SHA256_DIGEST_SIZE],address[50] = {0},hex_signature[132],*signature,hex_z[65];
	char nV;
	bool entrar = true;
	int bytes_random;
	msg_magic_hash(message,raw_z);
	tohex_dst(raw_z,sizeof(raw_z),hex_z);
	mpz_inits(k, r, s, z, publickey.x, publickey.y, R.x, R.y,k_inv, NULL);
	mpz_set_str(z, hex_z, 16);
	if(VERBOSE) gmp_printf("key: %0.64Zx\n",key);
	Scalar_Multiplication(G,&publickey,key);
	generate_straddress(&publickey,compressed,address);
	
	do	{
		do {
			bytes_random = mpz_geturandom(&k,32);
		}while(bytes_random != 32);
		if(VERBOSE) gmp_printf("Nonce: %0.64Zx\n",k);
		Scalar_Multiplication(G,&R,k);
		mpz_set(r,R.x);
		mpz_invert(k_inv,k,EC.n);
		
		mpz_mul(s,r,key);
		mpz_mod(s,s,EC.n);
		
		mpz_add(s,s,z);
		mpz_mod(s,s,EC.n);
		
		mpz_mul(s,s,k_inv);
		mpz_mod(s,s,EC.n);
	}while(mpz_cmp_ui(s,0) == 0);
	if(VERBOSE) gmp_printf("X: %0.64Zx\n",publickey.x);
	if(VERBOSE) gmp_printf("Y: %0.64Zx\n",publickey.y);
	if(VERBOSE) gmp_printf("S: %0.64Zx\n",s);
	if(VERBOSE) gmp_printf("R: %0.64Zx\n",r);
	if(VERBOSE) gmp_printf("R.y: %0.64Zx\n",R.y);
	if(VERBOSE) gmp_printf("Z: %0.64Zx\n",z);
	gmp_snprintf(hex_signature,sizeof(hex_signature),"20%0.64Zx%0.64Zx",r,s);
	signature = calloc(65,sizeof(char));
	if(signature == NULL)	{
		fprintf(stderr,"error: calloc()\n");
		exit(0);
	}
	hexs2bin(hex_signature,signature);
	for(int i = 0; i < 4 && entrar; i++)	{
		nV = 27 +i;
		if(compressed)
			nV += 4;
		signature[0] = nV;
		if(verify_message( address, signature, message) == 1){
			entrar = false;
		}
	}
	mpz_clears(k, r, s, z, publickey.x, publickey.y, R.x, R.y,k_inv, NULL);
	return signature;
}

void print_signature(char *message,char *address, char *signature_base64)	{
	printf("-----BEGIN BITCOIN SIGNED MESSAGE-----\n%s\n-----BEGIN BITCOIN SIGNATURE-----\n%s\n%s\n-----END BITCOIN SIGNATURE-----\n",message,address,signature_base64);
}

char *sign_message_b64(char *wifPrivateKey, char *message)	{
	char *signature,*encoded_signature;
	bool compressed = true;
	size_t len_output;
	if(wifPrivateKey[0] == '5')	{
		compressed = false;
	}
	signature = sign_message_with_private_key(wifPrivateKey,message,compressed);
	if(signature == NULL)
		return NULL;
	encoded_signature =  base64_encode(signature,65,&len_output);
	printf("base 64 output len: %li\n",len_output);
	free(signature);
	return encoded_signature;
}

char *sign_and_verify(char *wifPrivateKey, char *message, char *bitcoinaddress, bool compressed)	{
    char *sig = sign_message_with_private_key(wifPrivateKey, message, compressed);
	if(sig == NULL)
		return NULL;
    if(VERBOSE) printf("verify_message: %s\n", verify_message(bitcoinaddress, sig, message) ? "true": "false");
	if(verify_message(bitcoinaddress, sig, message))	{
		return sig;
	}
	else	{
		free(sig);
		return NULL;
	}
}


/*
the msg_magic function takes a message string as input and returns a new string
that is prefixed with the special Bitcoin "magic" prefix and the length of the original message. 
This allows the message to be properly identified as a Bitcoin signed message.
*/
char *msg_magic(char *message, int *len_output) {
	char *header;
	char *body;
	char *fullmessage;
	const char *header_message = "Bitcoin Signed Message:\n";
	int len_header_message;
	int len_body_message;
	header = msg_bytes((char*)header_message,&len_header_message);
	body = msg_bytes(message,&len_body_message);
	*len_output = len_header_message + len_body_message;
	fullmessage = calloc(*len_output + 1,sizeof(char));
	memcpy(fullmessage,header,len_header_message);
	memcpy(fullmessage+len_header_message,body,len_body_message);
	free(header);
	free(body);
	return fullmessage;
}


/*
This function calls to msg_magic and performs the double sha256 over the fullmessage
It estores the digest in th dst_digest variable
*/
void msg_magic_hash(char *message,char *dst_digest) {
	int len;
	char *fullmessage = msg_magic(message,&len);
	double_sha256(fullmessage,len,dst_digest);
	free(fullmessage);	
}

char *msg_bytes(char *message,int *len_output)	{
	int bytes_prefix;
	char *hextemp;
	unsigned char *message_formated;
	int len_message,len_message_op;
	len_message = strlen(message);
	len_message_op = len_message;
	message_formated = (unsigned char *)calloc(len_message+6,sizeof(unsigned char));
	if(len_message < 0xfd)	{
		bytes_prefix = 1;
		message_formated[0] = (unsigned char) len_message_op;
	}else if(len_message <= 0xffff)	{
		bytes_prefix = 3;
		message_formated[0] =  0xfd;
		message_formated[1] =  (unsigned char) len_message_op & 255;
		len_message_op >>= 8;
		message_formated[2] =  (unsigned char) len_message_op;
	}else if(len_message <= 0xffffffff)	{
		bytes_prefix = 5;
		message_formated[0] =  0xfe;
		message_formated[1] =  (unsigned char) len_message_op & 255;
		len_message_op >>= 8;
		message_formated[2] =  (unsigned char) len_message_op & 255;
		len_message_op >>= 8;
		message_formated[3] =  (unsigned char) len_message_op  & 255;
		len_message_op >>= 8;
		message_formated[4] =  (unsigned char) len_message_op;
	}else	{
		free(message_formated);
		fprintf(stderr,"Error: message too large\n");
		exit(0);
	}
	strncpy((char*)(message_formated+bytes_prefix),message,len_message);
	*len_output = bytes_prefix + len_message;
	return (char*)message_formated;
}

void double_sha256(uint8_t *input, size_t length, uint8_t *digest) {
  uint8_t intermediate_digest[SHA256_DIGEST_SIZE]; // to store the intermediate hash value
  sha256(input, length, intermediate_digest); // perform the first sha256 operation
  sha256(intermediate_digest, SHA256_DIGEST_SIZE, digest); // perform the second sha256 operation
}

bool verify_message(char *address,char *signature,char *message)	{
	struct Point R,Q,Z,aux_point;
	mpz_t r,s,z,r_inv,x,aux,y,beta,aux_recid,aux_order;
	bool compressed;
	char address_calculated[50],publickey[132];
	char hex_r[65],hex_s[65];
	char raw_z[32],hex_z[65];
	char v;
	int recid;
	if(address == NULL || signature == NULL || message == NULL)	{
		if(VERBOSE) printf("Some pointer is NULL\n");
		return false;
	}
	v = signature[0];
	
    if(v < 27 || v >= 35)	{
		if(VERBOSE) printf("First byte invalid: %i\n",(int)v);
		return false;
	}
	
	if(v >= 31){
        compressed = true;
        v -= 4;
	}
    else
        compressed = false;
	
	recid = v - 27;
	
	
	mpz_inits(beta,aux,aux_recid,r,s,z,x,y,R.x,R.y,Q.x,Q.y,aux_point.x,aux_point.y,Z.x,Z.y,r_inv , NULL);
	
	
	tohex_dst(signature +1 ,32,hex_r);
	tohex_dst(signature +33,32,hex_s);
	
	mpz_set_str(r,hex_r,16);
	mpz_set_str(s,hex_s,16);
	
	mpz_set_ui(aux_recid,recid);
	mpz_set(x,r);
	
	
	mpz_fdiv_q_ui(aux,aux_recid,2);
	mpz_mul(aux_order,EC.n,aux);
	mpz_add(x,x,aux_order);

	
	getYfromX(x,&beta);
	
	if((mpz_tstbit(beta,0) == 0 && recid % 2 == 1 ) || (mpz_tstbit(beta,0) == 1 && recid % 2 == 0 ))	{
		mpz_set(y,EC.p);
		mpz_sub(y,y,beta);
	}
	else	{
		mpz_set(y,beta);
	}
	if(VERBOSE) gmp_printf("Final X, Y : %0.64Zx %0.64Zx\n",x, y);
	
	mpz_set(R.x,x);
	mpz_set(R.y,y);
	
	mpz_invert(r_inv,r,EC.n);
	
	/**/
	msg_magic_hash(message,raw_z);
	

	tohex_dst(raw_z,sizeof(raw_z),hex_z);
	mpz_set_str(z,hex_z,16);
	if(VERBOSE) gmp_printf("Final R: %0.64Zx\nFinal S: %0.64Zx\nFinal Z: %0.64Zx\n",r,s,z);
	
	Scalar_Multiplication(G,&aux_point,z); // This is zG stored in aux_point
	Point_Negation(&aux_point,&Z);		// -zG stored in Z
	
	
	Scalar_Multiplication_custom(R,&aux_point,s);		// This is sR
	
	
	Point_Addition(&aux_point,&Z,&Q); // Q = (sR - eG)
	
	mpz_set(aux_point.x,Q.x);
	mpz_set(aux_point.y,Q.y);		// aux_point = Q
	

	Scalar_Multiplication_custom(aux_point,&Q,r_inv); // Q = r_inv *  (sR - eG)
	
	generate_straddress(&Q,compressed,address_calculated);
	
	if(VERBOSE)	{
		printf("Calculated address: %s\n",address_calculated);
		generate_strpublickey(&Q,compressed,publickey);
		printf("Calculated publickey %s: %s\n",compressed ? "compressed":"uncompressed" ,publickey);
		generate_strpublickey(&Q,!compressed,publickey);
		printf("Calculated publickey %s: %s\n",(!compressed) ? "compressed":"uncompressed" ,publickey);
	}
	mpz_clears(beta,aux,aux_recid,r,s,z,x,y,R.x,R.y,Q.x,Q.y,aux_point.x,aux_point.y,Z.x,Z.y,r_inv , NULL);
	if(strcmp(address_calculated,address) != 0)	{
		printf("Address missmatch %s != %s\n",address_calculated,address);
		return false;
	}
	return true;
}

void getYfromX(mpz_t x,mpz_t *y)	{
	mpz_t alpha;
	mpz_t mpz_aux,mpz_aux2;
	mpz_inits(alpha,mpz_aux,mpz_aux2,NULL);
	
	mpz_pow_ui(mpz_aux,x,3);
	mpz_add_ui(mpz_aux2,mpz_aux,7);
	mpz_mod(alpha,mpz_aux2,EC.p);
	
	mpz_add_ui(mpz_aux,EC.p,1);
	mpz_fdiv_q_ui(mpz_aux2,mpz_aux,4);
	
	mpz_powm(*y,alpha,mpz_aux2,EC.p);
	
	mpz_clears(alpha,mpz_aux,mpz_aux2,NULL);
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
	sha256(bin_digest+21, SHA256_DIGEST_SIZE, bin_digest+21);
	
	/* Get the address */
	if(!b58enc(dst,&pubaddress_size,bin_digest,25)){
		fprintf(stderr,"error b58enc\n");
	}
}

char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = calloc(*output_length + 2,sizeof(char));
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}

unsigned char *base64_decode(const char *data, size_t input_length,size_t *output_length) {

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}


void build_decoding_table() {
    decoding_table = malloc(256);
    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}

void base64_cleanup() {
    free(decoding_table);
}

void Scalar_Multiplication_custom(struct Point P, struct Point *R, mpz_t m)  {
	// Initialize temporary points for use in the algorithm
	struct Point Q, T;
	long no_of_bits, loop;
	mpz_init(Q.x);
	mpz_init(Q.y);
	mpz_init(T.x);
	mpz_init(T.y);
	no_of_bits = mpz_sizeinbase(m, 2);
	// Initialize the result point to the point at infinity (0,0)
	mpz_set_ui(R->x, 0);
	mpz_set_ui(R->y, 0);
	
	 // Check if the scalar value is 0 (in which case the result is the point at infinity)
	if(mpz_cmp_ui(m, 0) != 0)  {
		// Initialize the temporary point Q to the input point P
		mpz_set(Q.x, P.x);
		mpz_set(Q.y, P.y);
		
		// If the least significant bit of the scalar value is 1, set the result point to P
		if(mpz_tstbit(m, 0) == 1){
			mpz_set(R->x, P.x);
			mpz_set(R->y, P.y);
		}
		// Iterate over the remaining bits of the scalar value
		for(loop = 1; loop < no_of_bits; loop++) {
			// Double the temporary point Q
			Point_Doubling(&Q, &T);
			mpz_set(Q.x, T.x);
			mpz_set(Q.y, T.y);
			 // Save the current result point in T
			mpz_set(T.x, R->x);
			mpz_set(T.y, R->y);
			 // If the current bit of the scalar value is 1, add Q to the result point
			if(mpz_tstbit(m, loop))
				Point_Addition(&T, &Q, R);
		}
	}
	// Clear the memory used by the temporary points
	mpz_clear(Q.x);
	mpz_clear(Q.y);
	mpz_clear(T.x);
	mpz_clear(T.y);
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

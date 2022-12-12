#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "util.h"

char *ltrim(char *str, const char *seps)	{
	size_t totrim;
	if (seps == NULL) {
		seps = "\t\n\v\f\r ";
	}
	totrim = strspn(str, seps);
	if (totrim > 0) {
		size_t len = strlen(str);
		if (totrim == len) {
			str[0] = '\0';
		}
		else {
			memmove(str, str + totrim, len + 1 - totrim);
		}
	}
	return str;
}

char *rtrim(char *str, const char *seps)	{
	int i;
	if (seps == NULL) {
		seps = "\t\n\v\f\r ";
	}
	i = strlen(str) - 1;
	while (i >= 0 && strchr(seps, str[i]) != NULL) {
		str[i] = '\0';
		i--;
	}
	return str;
}

char *trim(char *str, const char *seps)	{
	return ltrim(rtrim(str, seps), seps);
}

int indexOf(char *s,const char **array,int length_array)	{
	int index = -1,i,continuar = 1;
	for(i = 0; i <length_array && continuar; i++)	{
		if(strcmp(s,array[i]) == 0)	{
			index = i;
			continuar = 0;
		}
	}
	return index;
}

char *nextToken(Tokenizer *t)	{
	if(t->current < t->n)	{
		t->current++;
		return t->tokens[t->current-1];
	}
	else {
		return  NULL;
	}
}
int hasMoreTokens(Tokenizer *t)	{
	return (t->current < t->n);
}

void stringtokenizer(char *data,Tokenizer *t)	{
	char *token;
	t->tokens = NULL;
	t->n = 0;
	t->current = 0;
	trim(data,"\t\n\r ");
	token = strtok(data," \t:");
	while(token != NULL)	{
		t->n++;
		t->tokens = (char**) realloc(t->tokens,sizeof(char*)*t->n);
		if(t->tokens == NULL)	{
			printf("Out of memory\n");
			exit(0);
		}
		t->tokens[t->n - 1] = token;
		token = strtok(NULL," \t");
	}
}

void freetokenizer(Tokenizer *t)	{
	if(t->n > 0)	{
		free(t->tokens);
	}
	memset(t,0,sizeof(Tokenizer));
}


/*
	Aux function to get the hexvalues of the data
*/
char* tohex(char *ptr, int length) {
	if(ptr == NULL || length <= 0)
		return NULL;
	// Allocate memory for the hexadecimal string and initialize it to zero
	char *hex_string = (char *)calloc((2 * length) + 1, sizeof(char));
	if(hex_string == NULL)
		fprintf(stderr,"Erro calloc()\n");
	// Convert the input string to a hexadecimal string
	for (int i = 0; i < length; i++) {
		snprintf((char*)(hex_string + (2 * i)), 3, "%.2x",(uint8_t) ptr[i]);
	}
	return hex_string;
}


void tohex_dst(char *ptr, int length,char *dst) {
	if(ptr == NULL || length <= 0)
		return;
	// Convert the input string to a hexadecimal string
	for (int i = 0; i < length; i++) {
		snprintf((char*)(dst + (2 * i)), 3, "%.2x",(uint8_t) ptr[i]);
		//snprintf(dst + 2 * i, 3, "%.2x", ptr[i]);
	}
	dst[length*2] = 0;
}


int hexs2bin(char *hex, unsigned char *out)	{
	int len;
	char b1;
	char b2;
	int i;
	if (hex == NULL || *hex == '\0' || out == NULL)
		return 0;

	len = strlen(hex);
	if (len % 2 != 0)
		return 0;
	len /= 2;
	memset(out, 0, len);
	for (i=0; i<len; i++) {
		if (!hexchr2bin(hex[i*2], &b1) || !hexchr2bin(hex[i*2+1], &b2)) {
			return 0;
		}
		out[i] = (b1 << 4) | b2;
	}
	return len;
}

int hexchr2bin(const char hex, char *out)	{
	if (out == NULL){
		return 0;
	}

	if (hex >= '0' && hex <= '9') {
		*out = hex - '0';
	} else if (hex >= 'A' && hex <= 'F') {
		*out = hex - 'A' + 10;
	} else if (hex >= 'a' && hex <= 'f') {
		*out = hex - 'a' + 10;
	} else {
		return 0;
	}

	return 1;
}

void addItemList(char *data, List *l)	{
	l->data = (char**) realloc(l->data,sizeof(char*)* (l->n +1));
	l->data[l->n] = data;
	l->n++;
}

int isValidHex(char *data)	{
	char c;
	int len,i,valid = 1;
	len = strlen(data);
	for(i = 0 ; i <  len && valid ;i++ )	{
		c = data[i];
		valid = ( (c >= '0' && c <='9') || (c >= 'A' && c <='F' ) || (c >= 'a' && c <='f' ) );
	}
	return valid;
}

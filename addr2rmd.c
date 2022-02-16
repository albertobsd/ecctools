/*
gcc -o addr2rmd addr2rmd.c util.o base58.o
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <inttypes.h>
#include "base58/libbase58.h"
#include "util.h"


#include <unistd.h>
/*

#include <pthread.h>
*/

int FLAG_INPUTFILE = 0;
int FLAG_OUTPUTFILE = 0;
int FLAG_STDOUT = 0;

char *input_filename,*output_filename;

int main(int argc, char **argv)	{
	FILE *fdin,*fdout;
	size_t len,expected;
	char c,buffer[1024],*hextemp,binout[100],outputbuffer[100];
	memset(buffer,0,1024);
	memset(binout,0,100);
	memset(outputbuffer,0,100);
	while ((c = getopt(argc, argv, "i:o:")) != -1) {
		switch(c)	{
			case 'i':
				FLAG_INPUTFILE = 1;
				input_filename = optarg;
			break;
			case 'o':
				FLAG_OUTPUTFILE = 1;
				output_filename = optarg;
			break;
		}
	}
	if(FLAG_OUTPUTFILE == 0)	{
		fdout = stdout;
		FLAG_OUTPUTFILE = 1;
		FLAG_STDOUT = 1;
	}
	else	{
		fdout = fopen(output_filename,"w");
	}
	if(FLAG_INPUTFILE && FLAG_OUTPUTFILE)	{
		fdin = fopen(input_filename,"r");
		if(fdin != NULL && fdout != NULL)	{
			while(!feof(fdin))	{
				hextemp = fgets(buffer,1024,fdin);
				if(hextemp == buffer);
				trim(buffer," \t\n\r");
				len = strlen(buffer);
				if(len > 0)	{
					expected = 25;
					if(b58tobin(binout,&expected,buffer,len)){
						if(expected != 25)	{
							fprintf(stderr,"Error invalid Address: %s\n",buffer);
						}
						else	{
							tohex_dst(binout+1,20,outputbuffer);
							fprintf(fdout,"%s\n",outputbuffer);
						}
					}
					else	{
						fprintf(stderr,"Error invalid Address: %s\n",buffer);
					}
					memset(buffer,0,len+1);
				}
			}
			fclose(fdin);
			if(FLAG_STDOUT == 0)
				fclose(fdout);
		}
		else	{
			fprintf(stderr,"error input/output files\n");
		}
	}
	else	{
		fprintf(stderr,"missing parameters\n");
	}	
}
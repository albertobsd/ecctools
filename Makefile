default:
	gcc -O3 -c bloom/bloom.c -o bloom.o
	gcc -O3 -c sha256/sha256.c -o sha256.o
	gcc -O3 -c base58/base58.c -o base58.o
	gcc -O3 -c rmd160/rmd160.c -o rmd160.o
	gcc -O3 -c xxhash/xxhash.c -o xxhash.o
	gcc -O3 -c gmpecc.c -o gmpecc.o
	gcc -O3 -c util.c -o util.o
	gcc -O3 -o rehashaddress rehashaddress.c gmpecc.o util.o sha256.o base58.o rmd160.o -lgmp
	gcc -O3 -o calculatefromkey calculatefromkey.c gmpecc.o util.o base58.o sha256.o rmd160.o -lgmp
	gcc -O3 -o calculatefrompublickey calculatefrompublickey.c gmpecc.o util.o base58.o sha256.o rmd160.o -lgmp
	gcc -O3 -o keydivision keydivision.c gmpecc.o util.o base58.o sha256.o rmd160.o -lgmp
	gcc -O3 -o keymath keymath.c gmpecc.o util.o  base58.o sha256.o rmd160.o -lgmp
	gcc -O3 -o modmath  modmath.c gmpecc.o util.o  base58.o sha256.o rmd160.o -lgmp
	gcc -O3 -o keygen keygen.c gmpecc.o util.o sha256.o base58.o rmd160.o -lgmp -lcrypto `libgcrypt-config --cflags --libs`
	gcc -O3 -o sharedsecret sharedsecret.c gmpecc.o util.o sha256.o base58.o rmd160.o -lgmp
	rm *.o
clean:
	rm -r *.o

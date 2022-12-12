/*
	gcc -o test_functions test_functions.c util.o
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "util.h"

void test_tohex();
void test_tohex_dst();



// Main function that runs the test
int main() {
	test_tohex();
	test_tohex_dst();
	return 0;
}

// Test function that checks if the tohex function works as expected
void test_tohex() {
	// Expected hexadecimal string
	char *expected = "48656c6c6f2c20576f726c6421";
	// Test input string
	char *input = "Hello, World!";
	int length = strlen(input);

	// Convert the input string to a hexadecimal string
	char *hex_str = tohex(input, length);
	// Check if the generated hexadecimal string is correct
	if (strcmp(hex_str, expected) == 0) {
		printf("tohex: PASS\n");
	} else {
		printf("tohex: FAIL\n");
	}

	// Free the memory allocated by the tohex function
	free(hex_str);
}


// Test function that checks if the tohex function works as expected
void test_tohex_dst() {
	// Test input string
	char *input = "Hello, World!";
	int length = strlen(input);
	char hex_str[27];

	// Convert the input string to a hexadecimal string and storing the result in hex_str
	tohex_dst(input, length,hex_str);

	// Expected hexadecimal string
	char *expected = "48656c6c6f2c20576f726c6421";

	// Check if the generated hexadecimal string is correct
	if (strcmp(hex_str, expected) == 0) {
		printf("tohex_dst: PASS\n");
	} else {
		printf("tohex_dst: FAIL\n");
	}
}

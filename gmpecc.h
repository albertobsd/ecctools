#ifndef GMPECC_H
#define GMPECC_H


struct Point {
	mpz_t x;
	mpz_t y;
};

struct Elliptic_Curve {
	mpz_t p;
	mpz_t n;
};


void Point_Doubling(struct Point *P, struct Point *R);
void Point_Addition(struct Point *P, struct Point *Q, struct Point *R);
void Scalar_Multiplication(struct Point P, struct Point *R, mpz_t m);
void Point_Negation(struct Point *A, struct Point *S);
void init_doublingG(struct Point *P);

struct Elliptic_Curve EC;
struct Point G;
struct Point DoublingG[256];


#endif

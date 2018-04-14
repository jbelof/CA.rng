/************************************************************************/
/* Cellular automata rule 30						*/
/*									*/
/* This implementation is for both 32 and 64 bit architectures, but is	*/
/* ideally implemented for 64.  The code has been generalized so that	*/
/* class III CA systems other than rule 30 can be utilized for research	*/
/* purposes.  The scheme makes use a register array upon which the rule	*/
/* is imposed - the next step in the automata is generated in the set	*/
/* of output registers.  Each end of the register array is 'wrapped'	*/
/* into a circular register; while this reduces the periodic interval	*/
/* of rule 30, the literature notes that this probablistically occurs	*/
/* on the order of modern cryptographic systems.  To simplify the logic	*/
/* the rule is implemented directly into the output register array, and	*/
/* then shifted one bit to the right at the end in order for the output	*/
/* to align.  Notice that rule 30 could be more cheaply implemented	*/
/* (at the cost of generality) by (left XOR (middle OR right)) - that	*/
/* is not done here.  The designated center bit of each iteration is	*/
/* used to generate the mantissa of the double float returned, as per	*/
/* Wolfram, "A New Kind of Science".  It is known that Mathematica uses	*/
/* this exact method in it's implementation of Random[].		*/
/*									*/
/* Benchmark results:							*/
/*									*/
/* compile with:							*/
/*	gcc -o rule30 -funroll-loops -O3 rule30.c			*/
/*									*/
/* @2005 Jonathan Belof							*/
/************************************************************************/


#include <limits.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>

#define WORDSIZE	64
//#define WORDSIZE	32

/* 64-bit masks */
#define RULE30		0x000000000000001E	/* 0000000000000000000000000000000000000000000000000000000000011110 */
#define RULE110		0x000000000000006e	/* 0000000000000000000000000000000000000000000000000000000001101110 */
#define RULE10		0x000000000000000a	/* 0000000000000000000000000000000000000000000000000000000000001010 */
#define RULE90		0x000000000000005a	/* 0000000000000000000000000000000000000000000000000000000001011010 */

#define CELL_MASK	0x0000000000000007	/* 0000000000000000000000000000000000000000000000000000000000000111 */
#define CENTER_MASK	0x0000000100000000	/* 0000000000000000000000000000000100000000000000000000000000000000 */
#define RHS_ONE		0x0000000000000001	/* 0000000000000000000000000000000000000000000000000000000000000001 */
#define LHS_ONE		0x8000000000000000	/* 1000000000000000000000000000000000000000000000000000000000000000 */
#define LHS_ZERO	0x7FFFFFFFFFFFFFFF	/* 0111111111111111111111111111111111111111111111111111111111111111 */
#define INNER_COUNT	0x00000000000000FF	/* 0000000000000000000000000000000000000000000000000000000011111111 */
#define INNER_ONE	0x0000000000000001	/* 0000000000000000000000000000000000000000000000000000000000000001 */
#define INNER_ZERO	0xFFFFFFFFFFFFFF00	/* 1111111111111111111111111111111111111111111111111111111100000000 */
#define OUTER_COUNT	0x0000000000FFFF00	/* 0000000000000000000000000000000000000000111111111111111100000000 */
#define OUTER_ONE	0x0000000000000100	/* 0000000000000000000000000000000000000001000000000000000000000000 */
#define OUTER_ZERO	0xFFFFFFFFFF0000FF	/* 1111111111111111111111111111111111111111000000000000000011111111 */

#define DEBUG

#ifdef DEBUG
/* debugging routine since printf still doesn't have binary output in the year 2005 */
void print_binary(unsigned long int in) {

	unsigned long int out = 0;
	int i;

	for(i = 0; i < WORDSIZE; i++) {

		out = in & LHS_ONE;	/* mask off all bits except LHS */
		if(out & LHS_ONE)
			printf("#");
		else
			printf(" ");

		in <<= RHS_ONE;

	}

}
#endif

void rule30(unsigned long int init) {

	register unsigned long int rule = RULE30;	/* the rule to enforce */
	register unsigned long int in_reg1 = 0,		/* input registers */
				   in_reg2 = 0,
				   in_reg3 = 0,
				   in_reg4 = 0,
				   in_reg5 = 0,
				   in_reg6 = 0,
				   in_reg7 = 0;
	register unsigned long int out_reg1 = 0,	/* output registers */
				   out_reg2 = 0,
				   out_reg3 = 0,
				   out_reg4 = 0,
				   out_reg5 = 0,
				   out_reg6 = 0,
				   out_reg7 = 0;
	register unsigned long int gp = 0;		/* general-purpose register:					*/
							/* 	- the right-most 8 bits are for the inner loop counter	*/
							/* 	- the next 16 bits are for the outer loop counter	*/
							/* 	- the left-most bit is for carries			*/
	static unsigned long int last_reg1,		/* static memory addrs to store results from the current run */
				 last_reg2,
				 last_reg3,
				 last_reg4,
				 last_reg5,
				 last_reg6,
				 last_reg7;

	/* start with initial config */
	if(init)
		in_reg1 = in_reg2 = in_reg3 = in_reg4 = in_reg5 = in_reg6 = init;
	else
		in_reg4 = CENTER_MASK;


#ifdef DEBUG
	printf("current rule: %d\n\n", (int)rule);

	/* print initial line */
	/*print_binary(in_reg3);*/ print_binary(in_reg4); /*print_binary(in_reg5);*/ printf("\n");
#endif /* DEBUG */

	while(1) {
	/*for((gp &= OUTER_ZERO); ((gp & OUTER_COUNT) >> 8) < 2550; gp += OUTER_ONE) {*/			/* <-- notice the fact that the increment here */
		for((gp &= INNER_ZERO); (gp & INNER_COUNT) < WORDSIZE; gp += INNER_ONE) {		/* will blow away the low-order bits doesn't matter */

			/* mask off first three bits and compare with rule */
			/* set the output register bit appropriately */
			out_reg1 |= ((rule >> (in_reg1 & CELL_MASK)) & RHS_ONE) << (gp & INNER_COUNT);
			out_reg2 |= ((rule >> (in_reg2 & CELL_MASK)) & RHS_ONE) << (gp & INNER_COUNT);
			out_reg3 |= ((rule >> (in_reg3 & CELL_MASK)) & RHS_ONE) << (gp & INNER_COUNT);
			out_reg4 |= ((rule >> (in_reg4 & CELL_MASK)) & RHS_ONE) << (gp & INNER_COUNT);
			out_reg5 |= ((rule >> (in_reg5 & CELL_MASK)) & RHS_ONE) << (gp & INNER_COUNT);
			out_reg6 |= ((rule >> (in_reg6 & CELL_MASK)) & RHS_ONE) << (gp & INNER_COUNT);
			out_reg7 |= ((rule >> (in_reg7 & CELL_MASK)) & RHS_ONE) << (gp & INNER_COUNT);

			/* rotate all input registers one bit to the right, preserve carry */
			gp &= LHS_ZERO;							/* clear the carry bit */
			gp |= ((in_reg7 & RHS_ONE) << (WORDSIZE - 1));			/* set carry bit if needed */
			in_reg7 >>= RHS_ONE;
			in_reg7 |= ((in_reg6 & RHS_ONE) << (WORDSIZE - 1));
			in_reg6 >>= RHS_ONE;
			in_reg6 |= ((in_reg5 & RHS_ONE) << (WORDSIZE - 1));
			in_reg5 >>= RHS_ONE;
			in_reg5 |= ((in_reg4 & RHS_ONE) << (WORDSIZE - 1));
			in_reg4 >>= RHS_ONE;
			in_reg4 |= ((in_reg3 & RHS_ONE) << (WORDSIZE - 1));
			in_reg3 >>= RHS_ONE;
			in_reg3 |= ((in_reg2 & RHS_ONE) << (WORDSIZE - 1));
			in_reg2 >>= RHS_ONE;
			in_reg2 |= ((in_reg1 & RHS_ONE) << (WORDSIZE - 1));
			in_reg1 >>= RHS_ONE;
			in_reg1 |= gp & LHS_ONE;

		}

		/* now must rotate output registers one bit to the left */
		gp &= LHS_ZERO;								/* clear the carry bit */
		gp |= out_reg1 & LHS_ONE;						/* set the carry bit if needed */
		out_reg1 <<= RHS_ONE;
		out_reg1 |= ((out_reg2 & LHS_ONE) >> (WORDSIZE - 1));
		out_reg2 <<= RHS_ONE;
		out_reg2 |= ((out_reg3 & LHS_ONE) >> (WORDSIZE - 1));
		out_reg3 <<= RHS_ONE;
		out_reg3 |= ((out_reg4 & LHS_ONE) >> (WORDSIZE - 1));
		out_reg4 <<= RHS_ONE;
		out_reg4 |= ((out_reg5 & LHS_ONE) >> (WORDSIZE - 1));
		out_reg5 <<= RHS_ONE;
		out_reg5 |= ((out_reg6 & LHS_ONE) >> (WORDSIZE - 1));
		out_reg6 <<= RHS_ONE;
		out_reg6 |= ((out_reg7 & LHS_ONE) >> (WORDSIZE - 1));
		out_reg7 <<= RHS_ONE;
		out_reg7 |=  ((gp & LHS_ONE) >> (WORDSIZE - 1));

		/* set output bits of double */

#ifdef DEBUG
		/* give visual output */
		print_binary(out_reg3); print_binary(out_reg4); print_binary(out_reg5); printf("\n");
#endif /* DEBUG */

		/* swap the input and output registers */
		in_reg1 = out_reg1;
		in_reg2 = out_reg2;
		in_reg3 = out_reg3;
		in_reg4 = out_reg4;
		in_reg5 = out_reg5;
		in_reg6 = out_reg6;
		in_reg7 = out_reg7;

		/* clear output registers */
		out_reg1 = out_reg2 = out_reg3 = out_reg4 = out_reg5 = out_reg6 = out_reg7 = 0;

	}

}

int main() {

	unsigned long int init = 0;

	rule30(init);

	exit(0);

}


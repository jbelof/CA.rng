/************************************************************************/
/* XR30256: An experimental cryptographic algorithm based upon CA rule30*/
/*									*/
/* Currently only implemented for 64-bit linux architecture.		*/
/*									*/
/* The key, plaintext and ciphertext are all 256-bit.  The algorithm	*/
/* works as follows:							*/
/*									*/
/* key scheduler:							*/
/*									*/
/* key: k1|k2|k3|k4							*/
/*									*/
/*		k1|k1+k1*k2|k1+k1*k3|k1+k1*k4				*/
/*			     |						*/
/*			     |CA256					*/
/*			     |						*/
/*			     V						*/
/*			     K1						*/
/*									*/
/*		k2+k2*k1|k2|k2+k2*k3|k2+k2*k4				*/
/*			     |						*/
/*			     |CA256					*/
/*			     |						*/
/*			     V						*/
/*			     K2						*/
/*			    etc.					*/
/*									*/
/* where KX is a 256-bit scheduled subkey and CA256 refers to 512	*/
/* iterations through rule 30.  The rule 30 state machine is implemented*/
/* with a 256-bit width and cyclic boundary conditions.			*/
/*									*/
/* The cipher is a 16 round Feistel network using an F-function of	*/
/* CA256 (i.e. 4 iterations of rule 30) where the input to F is initialy*/
/* the right or left plaintext block of length 128 bits expanded to	*/
/* 256 and then XOR'd with the subkey before running through the CA.	*/
/*									*/
/* F-function(KX, PY):							*/
/*									*/
/* 		|--------------------KX--------------------|		*/
/*				    XOR					*/
/*		|---------PY---------|---------PY----------|		*/
/*				     |					*/
/*				     |CA256				*/
/*				     |					*/
/*				     V					*/
/*		|---------PY'--------|---------PY''--------|		*/
/*			  ^		       ^			*/
/*			  |---------XOR--------|			*/
/*				     |					*/
/*				     |					*/
/*				     V					*/
/*			  |-----F(KX, PY)------|			*/
/*									*/
/*									*/
/* The Feistel network takes the usual form:				*/
/*									*/
/* 16 iterations							*/
/*									*/
/*		|----------P1--------|----------P2--------|		*/
/*			   |		        /|			*/
/*			   |		       / |			*/
/*			   |		      /  |			*/
/*			   |	    	  F(K1)  |			*/
/*			   |		    /    |			*/
/*			   |		   /     |			*/
/*			   |		  /      |			*/
/*			   |	         /       |			*/
/*			   |	        /        |			*/
/*			  XOR<---------/         |			*/
/*			   |	  	         |			*/
/*			   V		         V			*/
/*			   \		        /			*/
/*			    \		       /   			*/
/*			     \		      /    			*/
/*			      \		     /     			*/
/*			       \	    /				*/
/*				\	   /				*/
/*				 \	  /				*/
/*				  \      /				*/
/*				   \    /				*/
/*				    \  /				*/
/*				     \/					*/
/*				     /\					*/
/*				    /  \				*/
/*				   /	\				*/
/*				  /	 \				*/
/*				 /	  \				*/
/*				/	   \				*/
/*			       /	    \				*/
/*			      /		     \				*/
/*			     /		      \				*/
/*			    /		       \			*/
/*			   /			\			*/
/*			   |		        /|			*/
/*			   |		       / |			*/
/*			   |		      /  |			*/
/*			   |	    	  F(K2)  |			*/
/*			   |		    /    |			*/
/*			   |		   /     |			*/
/*			   |		  /      |			*/
/*			   |	         /       |			*/
/*			   |	        /        |			*/
/*			  XOR<---------/         |			*/
/*			   |	  	         |			*/
/*			   V		         V			*/
/*			   \		        /			*/
/*			    \		       /   			*/
/*			     \		      /    			*/
/*			      \		     /     			*/
/*			       \	    /				*/
/*				\	   /				*/
/*				 \	  /				*/
/*				  \      /				*/
/*				   \    /				*/
/*				    \  /				*/
/*				     \/					*/
/*				     /\					*/
/*				    /  \				*/
/*				   /	\				*/
/*				  /	 \				*/
/*				 /	  \				*/
/*				/	   \				*/
/*			       /	    \				*/
/*			      /		     \				*/
/*			     /		      \				*/
/*			    /		       \			*/
/*			   /			\			*/
/*			   |		        /|			*/
/*			   |		       / |			*/
/*			   |		      /  |			*/
/*			   |	    	  F(K3)  |			*/
/*			   |		    /    |			*/
/*			   |		   /     |			*/
/*			   |		  /      |			*/
/*			   |	         /       |			*/
/*			   |	        /        |			*/
/*			  XOR<---------/         |			*/
/*			   |	  	         |			*/
/*			   V		         V			*/
/*			   \		        /			*/
/*			    \		       /   			*/
/*			     \		      /    			*/
/*			      \		     /     			*/
/*			       \	    /				*/
/*				\	   /				*/
/*				 \	  /				*/
/*				  \      /				*/
/*				   \    /				*/
/*				    \  /				*/
/*				     \/					*/
/*				     /\					*/
/*				    /  \				*/
/*				   /	\				*/
/*				  /	 \				*/
/*				 /	  \				*/
/*				/	   \				*/
/*			       /	    \				*/
/*			      /		     \				*/
/*			     /		      \				*/
/*			    /		       \			*/
/*			   /			\			*/
/*			   |		        /|			*/
/*			   |		       / |			*/
/*			   |		      /  |			*/
/*			   |	    	  F(K4)  |			*/
/*			   |		    /    |			*/
/*			   |		   /     |			*/
/*			   |		  /      |			*/
/*			   |	         /       |			*/
/*			   |	        /        |			*/
/*			  XOR<---------/         |			*/
/*			   |	  	         |			*/
/*			   V		         V			*/
/*		|----------C1--------|----------C2--------|		*/
/*				    ...					*/
/*			    15 more iterations				*/
/* and decryption is the same except that the order of the subkeys	*/
/* is reversed.								*/
/*									*/
/* Security:								*/
/* How difficult is it to reverse the CA?  It is easily noticed that	*/
/* combinatorial reversal yields either singluar or double degenerate	*/
/* solutions for each step backwards.  The idea is that in order to	*/
/* reverse CA256 one would have to consider at most 2^256 possible	*/
/* solutions due to the degeneracy...but what is the most probable	*/
/* order of this?  It is entirely possible that 1/2 of the steps yield	*/
/* a singular solution, which would give 1.5^256 possibilities.		*/
/* Also, at various steps backwards it is apparent that the probability	*/
/* of the preceding bit being a 1 or 0 can be 75% (3 out of the 4	*/
/* possibilities) and so a probablistic attack may well reduced the	*/
/* order of magnitude of possibilities drastically.			*/
/* It is also known that there are clearly weak keys possible, since	*/
/* there are initial states to the CA that yield repeating patterns.	*/
/* This cipher should be considered merely a research curiousity for	*/
/* the moment.								*/
/*									*/
/* This cipher is slow in it's current implementation - mainly because	*/
/* it is generalized for any CA.  R30 specific code would be fast.	*/
/*									*/
/* compile with:							*/
/*	gcc -O3 -o rc rule30.crypt.c					*/
/*									*/
/* @2005 Jonathan Belof							*/
/************************************************************************/

/*#define BENCHMARK*/
#define DEBUG

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>

#include <time.h>

#define WORDSIZE	64
//#define WORDSIZE	32

#if WORDSIZE == 64
/* 64-bit masks */
#define RULE30		0x000000000000001E	/* 0000000000000000000000000000000000000000000000000000000000011110 */
#define RULE110		0x000000000000006E	/* 0000000000000000000000000000000000000000000000000000000001101110 */
#define RULE10		0x000000000000000A	/* 0000000000000000000000000000000000000000000000000000000000001010 */
#define RULE90		0x000000000000005A	/* 0000000000000000000000000000000000000000000000000000000001011010 */

#define CELL_MASK	0x0000000000000007	/* 0000000000000000000000000000000000000000000000000000000000000111 */
#define RHS_ONE		0x0000000000000001	/* 0000000000000000000000000000000000000000000000000000000000000001 */
#define LHS_ONE		0x8000000000000000	/* 1000000000000000000000000000000000000000000000000000000000000000 */
#define LHS_ZERO	0x7FFFFFFFFFFFFFFF	/* 0111111111111111111111111111111111111111111111111111111111111111 */
#define INNER_COUNT	0x00000000000000FF	/* 0000000000000000000000000000000000000000000000000000000011111111 */
#define INNER_ONE	0x0000000000000001	/* 0000000000000000000000000000000000000000000000000000000000000001 */
#define INNER_ZERO	0xFFFFFFFFFFFFFF00	/* 1111111111111111111111111111111111111111111111111111111100000000 */
#define OUTER_COUNT	0x0000000000FFFF00	/* 0000000000000000000000000000000000000000111111111111111100000000 */
#define OUTER_ONE	0x0000000000000100	/* 0000000000000000000000000000000000000001000000000000000000000000 */
#define OUTER_ZERO	0xFFFFFFFFFF0000FF	/* 1111111111111111111111111111111111111111000000000000000011111111 */
#define DELTA_COUNT	0x0000000000000008	/* 0000000000000000000000000000000000000000000000000000000000001000 */
#define DELTA_ROUNDS	0x0000000000000018	/* 0000000000000000000000000000000000000000000000000000000000011000 */
#define ROUNDS_COUNT	0x000000FFFF000000	/* 0000000000000000000000001111111111111111000000000000000000000000 */
#define ROUNDS_ZERO	0xFFFFFF0000FFFFFF	/* 1111111111111111111111110000000000000000111111111111111111111111 */
#define ROUNDS_ONE	0x0000000001000000	/* 0000000000000000000000000000000000000001000000000000000000000000 */
#define CA256		0x00000000000000FF	/* 0000000000000000000000000000000000000000000000000000000011111111 */
#define ROUNDS		0x0000000000000010	/* 0000000000000000000000000000000000000000000000000000000000010000 */
#else
/* 32-bit masks */
#define RULE30		0x0000001E	/* 00000000000000000000000000011110 */
#define RULE110		0x0000006E	/* 00000000000000000000000001101110 */
#define RULE10		0x0000000A	/* 00000000000000000000000000001010 */
#define RULE90		0x0000005A	/* 00000000000000000000000001011010 */

#define CELL_MASK	0x00000007	/* 00000000000000000000000000000111 */
#define RHS_ONE		0x00000001	/* 00000000000000000000000000000001 */
#define LHS_ONE		0x80000000	/* 10000000000000000000000000000000 */
#define LHS_ZERO	0x7FFFFFFF	/* 01111111111111111111111111111111 */
#define INNER_COUNT	0x000000FF	/* 00000000000000000000000011111111 */
#define INNER_ONE	0x00000001	/* 00000000000000000000000000000001 */
#define INNER_ZERO	0xFFFFFF00	/* 11111111111111111111111100000000 */
#define OUTER_COUNT	0x00FFFF00	/* 00000000111111111111111100000000 */
#define OUTER_ONE	0x00000100	/* 00000001000000000000000000000000 */
#define OUTER_ZERO	0xFF0000FF	/* 11111111000000000000000011111111 */
#define DELTA_COUNT	0x00000008	/* 00000000000000000000000000001000 */
#define CA256		0x000000FF	/* 00000000000000000000000011111111 */
#define ROUNDS		0x00000010	/* 00000000000000000000000000010000 */
#endif /* WORDSIZE == 64 */

struct scheduled_key {

	unsigned long int key_1[4];
	unsigned long int key_2[4];
	unsigned long int key_3[4];
	unsigned long int key_4[4];

};

/* debugging routine since printf still doesn't have binary output in the year 2005 */
void print_binary(unsigned long int in) {

	unsigned long int out = 0;
	int i;

	for(i = 0; i < WORDSIZE; i++) {

		out = in & LHS_ONE;	/* mask off all bits except LHS */
		if(out & LHS_ONE)
			printf("1");
		else
			printf("0");

		in <<= RHS_ONE;

	}

}

#if WORDSIZE == 64 /* 64-bit */

struct scheduled_key * xr30256_key_schedule(unsigned long int *key) {

	struct scheduled_key *skey;			/* the scheduled key segments */
	register unsigned long int rule = RULE30;	/* the rule to enforce */
	register unsigned long int key_in_reg1 = 0,	/* key input registers */
				   key_in_reg2 = 0,
				   key_in_reg3 = 0,
				   key_in_reg4 = 0;
	register unsigned long int key_out_reg1 = 0,	/* key output registers */
				   key_out_reg2 = 0,
				   key_out_reg3 = 0,
				   key_out_reg4 = 0;
	register unsigned long int key_carry = 0;	/* used to perform key rotation */
	register unsigned long int mp = 0;		/* multi-purpose register:					*/
							/* 	- the right-most 8 bits are for the inner loop counter	*/
							/* 	- the next 16 bits are for the outer loop counter	*/
							/* 	- the left-most bit is for carries			*/

	/* allocate space for the key segments that have been scheduled through the CA state machine */
	skey = calloc(1, sizeof(struct scheduled_key));

	/* load the 1st key segment */
	key_in_reg1 = *(key + 0);
	key_in_reg2 = *(key + 0) + (*(key + 0))*(*(key + 1));
	key_in_reg3 = *(key + 0) + (*(key + 0))*(*(key + 2));
	key_in_reg4 = *(key + 0) + (*(key + 0))*(*(key + 3));

	/* K1/CA256 */
	for((mp &= OUTER_ZERO); ((mp & OUTER_COUNT) >> DELTA_COUNT) < CA256; mp += OUTER_ONE) {		/* <-- notice the fact that the increment here */
													/* will blow away the low-order bits doesn't matter */
		/* clear output registers */
		key_out_reg1 = key_out_reg2 = key_out_reg3 = key_out_reg4 = 0;

		for((mp &= INNER_ZERO); (mp & INNER_COUNT) < WORDSIZE; mp += INNER_ONE) {

			/* mask off first three bits and compare with rule */
			/* set the output register bit appropriately */
			key_out_reg1 |= ((rule >> (key_in_reg1 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
			key_out_reg2 |= ((rule >> (key_in_reg2 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
			key_out_reg3 |= ((rule >> (key_in_reg3 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
			key_out_reg4 |= ((rule >> (key_in_reg4 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);

			/* rotate all input registers one bit to the right, preserve carry */
			mp &= LHS_ZERO;							/* clear the carry bit */
			mp |= ((key_in_reg4 & RHS_ONE) << (WORDSIZE - 1));		/* set carry bit if needed */
			key_in_reg4 >>= RHS_ONE;
			key_in_reg4 |= ((key_in_reg3 & RHS_ONE) << (WORDSIZE - 1));
			key_in_reg3 >>= RHS_ONE;
			key_in_reg3 |= ((key_in_reg2 & RHS_ONE) << (WORDSIZE - 1));
			key_in_reg2 >>= RHS_ONE;
			key_in_reg2 |= ((key_in_reg1 & RHS_ONE) << (WORDSIZE - 1));
			key_in_reg1 >>= RHS_ONE;
			key_in_reg1 |= mp & LHS_ONE;

		}

		/* now must rotate output registers one bit to the left */
		mp &= LHS_ZERO;								/* clear the carry bit */
		mp |= key_out_reg1 & LHS_ONE;						/* set the carry bit if needed */
		key_out_reg1 <<= RHS_ONE;
		key_out_reg1 |= ((key_out_reg2 & LHS_ONE) >> (WORDSIZE - 1));
		key_out_reg2 <<= RHS_ONE;
		key_out_reg2 |= ((key_out_reg3 & LHS_ONE) >> (WORDSIZE - 1));
		key_out_reg3 <<= RHS_ONE;
		key_out_reg3 |= ((key_out_reg4 & LHS_ONE) >> (WORDSIZE - 1));
		key_out_reg4 <<= RHS_ONE;
		key_out_reg4 |=  ((mp & LHS_ONE) >> (WORDSIZE - 1));

		/* swap the input and output registers */
		key_in_reg1 = key_out_reg1;
		key_in_reg2 = key_out_reg2;
		key_in_reg3 = key_out_reg3;
		key_in_reg4 = key_out_reg4;

	}

	skey->key_1[0] = key_in_reg1;
	skey->key_1[1] = key_in_reg2;
	skey->key_1[2] = key_in_reg3;
	skey->key_1[3] = key_in_reg4;

#ifdef DEBUG
	printf("K1:\n");
	print_binary(skey->key_1[0]); print_binary(skey->key_1[1]); print_binary(skey->key_1[2]); print_binary(skey->key_1[3]); printf("\n");
#endif /* DEBUG */

	/* load the 2nd key segment */
	key_in_reg1 = *(key + 1) + (*(key + 1))*(*(key + 0));
	key_in_reg2 = *(key + 1);
	key_in_reg3 = *(key + 1) + (*(key + 1))*(*(key + 2));
	key_in_reg4 = *(key + 1) + (*(key + 1))*(*(key + 3));

	/* K2/CA256 */
	for((mp &= OUTER_ZERO); ((mp & OUTER_COUNT) >> DELTA_COUNT) < CA256; mp += OUTER_ONE) {		/* <-- notice the fact that the increment here */
													/* will blow away the low-order bits doesn't matter */
		/* clear output registers */
		key_out_reg1 = key_out_reg2 = key_out_reg3 = key_out_reg4 = 0;

		for((mp &= INNER_ZERO); (mp & INNER_COUNT) < WORDSIZE; mp += INNER_ONE) {

			/* mask off first three bits and compare with rule */
			/* set the output register bit appropriately */
			key_out_reg1 |= ((rule >> (key_in_reg1 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
			key_out_reg2 |= ((rule >> (key_in_reg2 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
			key_out_reg3 |= ((rule >> (key_in_reg3 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
			key_out_reg4 |= ((rule >> (key_in_reg4 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);

			/* rotate all input registers one bit to the right, preserve carry */
			mp &= LHS_ZERO;							/* clear the carry bit */
			mp |= ((key_in_reg4 & RHS_ONE) << (WORDSIZE - 1));		/* set carry bit if needed */
			key_in_reg4 >>= RHS_ONE;
			key_in_reg4 |= ((key_in_reg3 & RHS_ONE) << (WORDSIZE - 1));
			key_in_reg3 >>= RHS_ONE;
			key_in_reg3 |= ((key_in_reg2 & RHS_ONE) << (WORDSIZE - 1));
			key_in_reg2 >>= RHS_ONE;
			key_in_reg2 |= ((key_in_reg1 & RHS_ONE) << (WORDSIZE - 1));
			key_in_reg1 >>= RHS_ONE;
			key_in_reg1 |= mp & LHS_ONE;

		}

		/* now must rotate output registers one bit to the left */
		mp &= LHS_ZERO;								/* clear the carry bit */
		mp |= key_out_reg1 & LHS_ONE;						/* set the carry bit if needed */
		key_out_reg1 <<= RHS_ONE;
		key_out_reg1 |= ((key_out_reg2 & LHS_ONE) >> (WORDSIZE - 1));
		key_out_reg2 <<= RHS_ONE;
		key_out_reg2 |= ((key_out_reg3 & LHS_ONE) >> (WORDSIZE - 1));
		key_out_reg3 <<= RHS_ONE;
		key_out_reg3 |= ((key_out_reg4 & LHS_ONE) >> (WORDSIZE - 1));
		key_out_reg4 <<= RHS_ONE;
		key_out_reg4 |=  ((mp & LHS_ONE) >> (WORDSIZE - 1));

		/* swap the input and output registers */
		key_in_reg1 = key_out_reg1;
		key_in_reg2 = key_out_reg2;
		key_in_reg3 = key_out_reg3;
		key_in_reg4 = key_out_reg4;

	}

	skey->key_2[0] = key_in_reg1;
	skey->key_2[1] = key_in_reg2;
	skey->key_2[2] = key_in_reg3;
	skey->key_2[3] = key_in_reg4;

#ifdef DEBUG
	printf("K2:\n");
	print_binary(skey->key_2[0]); print_binary(skey->key_2[1]); print_binary(skey->key_2[2]); print_binary(skey->key_2[3]); printf("\n");
#endif /* DEBUG */

	/* load the 3rd key segment */
	key_in_reg1 = *(key + 2) + (*(key + 2))*(*(key + 0));
	key_in_reg2 = *(key + 2) + (*(key + 2))*(*(key + 1));
	key_in_reg3 = *(key + 2);
	key_in_reg4 = *(key + 2) + (*(key + 2))*(*(key + 3));

	/* K3/CA256 */
	for((mp &= OUTER_ZERO); ((mp & OUTER_COUNT) >> DELTA_COUNT) < CA256; mp += OUTER_ONE) {		/* <-- notice the fact that the increment here */
													/* will blow away the low-order bits doesn't matter */
		/* clear output registers */
		key_out_reg1 = key_out_reg2 = key_out_reg3 = key_out_reg4 = 0;

		for((mp &= INNER_ZERO); (mp & INNER_COUNT) < WORDSIZE; mp += INNER_ONE) {

			/* mask off first three bits and compare with rule */
			/* set the output register bit appropriately */
			key_out_reg1 |= ((rule >> (key_in_reg1 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
			key_out_reg2 |= ((rule >> (key_in_reg2 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
			key_out_reg3 |= ((rule >> (key_in_reg3 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
			key_out_reg4 |= ((rule >> (key_in_reg4 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);

			/* rotate all input registers one bit to the right, preserve carry */
			mp &= LHS_ZERO;							/* clear the carry bit */
			mp |= ((key_in_reg4 & RHS_ONE) << (WORDSIZE - 1));		/* set carry bit if needed */
			key_in_reg4 >>= RHS_ONE;
			key_in_reg4 |= ((key_in_reg3 & RHS_ONE) << (WORDSIZE - 1));
			key_in_reg3 >>= RHS_ONE;
			key_in_reg3 |= ((key_in_reg2 & RHS_ONE) << (WORDSIZE - 1));
			key_in_reg2 >>= RHS_ONE;
			key_in_reg2 |= ((key_in_reg1 & RHS_ONE) << (WORDSIZE - 1));
			key_in_reg1 >>= RHS_ONE;
			key_in_reg1 |= mp & LHS_ONE;

		}

		/* now must rotate output registers one bit to the left */
		mp &= LHS_ZERO;								/* clear the carry bit */
		mp |= key_out_reg1 & LHS_ONE;						/* set the carry bit if needed */
		key_out_reg1 <<= RHS_ONE;
		key_out_reg1 |= ((key_out_reg2 & LHS_ONE) >> (WORDSIZE - 1));
		key_out_reg2 <<= RHS_ONE;
		key_out_reg2 |= ((key_out_reg3 & LHS_ONE) >> (WORDSIZE - 1));
		key_out_reg3 <<= RHS_ONE;
		key_out_reg3 |= ((key_out_reg4 & LHS_ONE) >> (WORDSIZE - 1));
		key_out_reg4 <<= RHS_ONE;
		key_out_reg4 |=  ((mp & LHS_ONE) >> (WORDSIZE - 1));

		/* swap the input and output registers */
		key_in_reg1 = key_out_reg1;
		key_in_reg2 = key_out_reg2;
		key_in_reg3 = key_out_reg3;
		key_in_reg4 = key_out_reg4;

	}

	skey->key_3[0] = key_in_reg1;
	skey->key_3[1] = key_in_reg2;
	skey->key_3[2] = key_in_reg3;
	skey->key_3[3] = key_in_reg4;

#ifdef DEBUG
	printf("K3:\n");
	print_binary(skey->key_3[0]); print_binary(skey->key_3[1]); print_binary(skey->key_3[2]); print_binary(skey->key_3[3]); printf("\n");
#endif /* DEBUG */

	/* load the 4th key segment */
	key_in_reg1 = *(key + 3) + (*(key + 3))*(*(key + 0));
	key_in_reg2 = *(key + 3) + (*(key + 3))*(*(key + 1));
	key_in_reg3 = *(key + 3) + (*(key + 3))*(*(key + 2));
	key_in_reg4 = *(key + 3);

	/* K4/CA256 */
	for((mp &= OUTER_ZERO); ((mp & OUTER_COUNT) >> DELTA_COUNT) < CA256; mp += OUTER_ONE) {		/* <-- notice the fact that the increment here */
													/* will blow away the low-order bits doesn't matter */
		/* clear output registers */
		key_out_reg1 = key_out_reg2 = key_out_reg3 = key_out_reg4 = 0;

		for((mp &= INNER_ZERO); (mp & INNER_COUNT) < WORDSIZE; mp += INNER_ONE) {

			/* mask off first three bits and compare with rule */
			/* set the output register bit appropriately */
			key_out_reg1 |= ((rule >> (key_in_reg1 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
			key_out_reg2 |= ((rule >> (key_in_reg2 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
			key_out_reg3 |= ((rule >> (key_in_reg3 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
			key_out_reg4 |= ((rule >> (key_in_reg4 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);

			/* rotate all input registers one bit to the right, preserve carry */
			mp &= LHS_ZERO;							/* clear the carry bit */
			mp |= ((key_in_reg4 & RHS_ONE) << (WORDSIZE - 1));		/* set carry bit if needed */
			key_in_reg4 >>= RHS_ONE;
			key_in_reg4 |= ((key_in_reg3 & RHS_ONE) << (WORDSIZE - 1));
			key_in_reg3 >>= RHS_ONE;
			key_in_reg3 |= ((key_in_reg2 & RHS_ONE) << (WORDSIZE - 1));
			key_in_reg2 >>= RHS_ONE;
			key_in_reg2 |= ((key_in_reg1 & RHS_ONE) << (WORDSIZE - 1));
			key_in_reg1 >>= RHS_ONE;
			key_in_reg1 |= mp & LHS_ONE;

		}

		/* now must rotate output registers one bit to the left */
		mp &= LHS_ZERO;								/* clear the carry bit */
		mp |= key_out_reg1 & LHS_ONE;						/* set the carry bit if needed */
		key_out_reg1 <<= RHS_ONE;
		key_out_reg1 |= ((key_out_reg2 & LHS_ONE) >> (WORDSIZE - 1));
		key_out_reg2 <<= RHS_ONE;
		key_out_reg2 |= ((key_out_reg3 & LHS_ONE) >> (WORDSIZE - 1));
		key_out_reg3 <<= RHS_ONE;
		key_out_reg3 |= ((key_out_reg4 & LHS_ONE) >> (WORDSIZE - 1));
		key_out_reg4 <<= RHS_ONE;
		key_out_reg4 |=  ((mp & LHS_ONE) >> (WORDSIZE - 1));

		/* swap the input and output registers */
		key_in_reg1 = key_out_reg1;
		key_in_reg2 = key_out_reg2;
		key_in_reg3 = key_out_reg3;
		key_in_reg4 = key_out_reg4;

	}

	skey->key_4[0] = key_in_reg1;
	skey->key_4[1] = key_in_reg2;
	skey->key_4[2] = key_in_reg3;
	skey->key_4[3] = key_in_reg4;

#ifdef DEBUG
	printf("K4:\n");
	print_binary(skey->key_4[0]); print_binary(skey->key_4[1]); print_binary(skey->key_4[2]); print_binary(skey->key_4[3]); printf("\n");
#endif /* DEBUG */

	return(skey);

}


void xr30256_encrypt(struct scheduled_key *key, unsigned long int *plaintext, unsigned long int *ciphertext) {

	register unsigned long int rule = RULE30;	/* the rule to enforce */
	register unsigned long int key_in_reg1 = 0,	/* key input registers */
				   key_in_reg2 = 0,
				   key_in_reg3 = 0,
				   key_in_reg4 = 0;
	register unsigned long int key_out_reg1 = 0,	/* key output registers */
				   key_out_reg2 = 0,
				   key_out_reg3 = 0,
				   key_out_reg4 = 0;
	register unsigned long int plain_1 = 0,
				   plain_2 = 0,
				   plain_3 = 0,
				   plain_4 = 0;
	register unsigned long int key_carry = 0;	/* used to perform key rotation */
	register unsigned long int mp = 0;		/* multi-purpose register:					*/
							/* 	- the right-most 8 bits are for the inner loop counter	*/
							/* 	- the next 16 bits are for the outer loop counter	*/
							/*	- the next 16 bits are for the rounds counter		*/
							/* 	- the left-most bit is for carries			*/

	/* load the plaintext */
	plain_1 = *(plaintext + 0);
	plain_2 = *(plaintext + 1);
	plain_3 = *(plaintext + 2);
	plain_4 = *(plaintext + 3);

	/* initialize with the right-half */
	key_in_reg1 ^= plain_3;
	key_in_reg2 ^= plain_4;
	key_in_reg3 = key_in_reg1;
	key_in_reg4 = key_in_reg2;

	for(mp &= ROUNDS_ZERO; ((mp & ROUNDS_COUNT) >> DELTA_ROUNDS) < ROUNDS; mp += ROUNDS_ONE) {

		/****************************/
		/***** START F-function *****/
		/****************************/
		/* load the first scheduled subkey */
		key_in_reg1 ^= key->key_1[0];
		key_in_reg2 ^= key->key_1[1];
		key_in_reg3 ^= key->key_1[2];
		key_in_reg4 ^= key->key_1[3];

		/* K1/CA256 */
		for((mp &= OUTER_ZERO); ((mp & OUTER_COUNT) >> DELTA_COUNT) < CA256; mp += OUTER_ONE) {		/* <-- notice the fact that the increment here */
														/* will blow away the low-order bits doesn't matter */
			/* clear output registers */
			key_out_reg1 = key_out_reg2 = key_out_reg3 = key_out_reg4 = 0;

			for((mp &= INNER_ZERO); (mp & INNER_COUNT) < WORDSIZE; mp += INNER_ONE) {

				/* mask off first three bits and compare with rule */
				/* set the output register bit appropriately */
				key_out_reg1 |= ((rule >> (key_in_reg1 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg2 |= ((rule >> (key_in_reg2 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg3 |= ((rule >> (key_in_reg3 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg4 |= ((rule >> (key_in_reg4 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);

				/* rotate all input registers one bit to the right, preserve carry */
				mp &= LHS_ZERO;							/* clear the carry bit */
				mp |= ((key_in_reg4 & RHS_ONE) << (WORDSIZE - 1));		/* set carry bit if needed */
				key_in_reg4 >>= RHS_ONE;
				key_in_reg4 |= ((key_in_reg3 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg3 >>= RHS_ONE;
				key_in_reg3 |= ((key_in_reg2 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg2 >>= RHS_ONE;
				key_in_reg2 |= ((key_in_reg1 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg1 >>= RHS_ONE;
				key_in_reg1 |= mp & LHS_ONE;

			}

			/* now must rotate output registers one bit to the left */
			mp &= LHS_ZERO;								/* clear the carry bit */
			mp |= key_out_reg1 & LHS_ONE;						/* set the carry bit if needed */
			key_out_reg1 <<= RHS_ONE;
			key_out_reg1 |= ((key_out_reg2 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg2 <<= RHS_ONE;
			key_out_reg2 |= ((key_out_reg3 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg3 <<= RHS_ONE;
			key_out_reg3 |= ((key_out_reg4 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg4 <<= RHS_ONE;
			key_out_reg4 |=  ((mp & LHS_ONE) >> (WORDSIZE - 1));

			/* swap the input and output registers */
			key_in_reg1 = key_out_reg1;
			key_in_reg2 = key_out_reg2;
			key_in_reg3 = key_out_reg3;
			key_in_reg4 = key_out_reg4;

		}

		/* XOR right and left half together and replicate result in both key halves */
		key_in_reg1 ^= key_in_reg3;
		key_in_reg2 ^= key_in_reg4;
		key_in_reg3 = key_in_reg1;
		key_in_reg4 = key_in_reg2;
		/**************************/
		/***** END F-function *****/
		/**************************/

		/* Feistel XOR with left-half */
		key_in_reg1 ^= plain_1;
		key_in_reg2 ^= plain_2;
		key_in_reg3 = key_in_reg1;
		key_in_reg4 = key_in_reg2;
		plain_1 = key_in_reg1;
		plain_2 = key_in_reg2;

		/****************************/
		/***** START F-function *****/
		/****************************/
		/* load the second scheduled subkey */
		key_in_reg1 ^= key->key_2[0];
		key_in_reg2 ^= key->key_2[1];
		key_in_reg3 ^= key->key_2[2];
		key_in_reg4 ^= key->key_2[3];

		/* K2/CA256 */
		for((mp &= OUTER_ZERO); ((mp & OUTER_COUNT) >> DELTA_COUNT) < CA256; mp += OUTER_ONE) {		/* <-- notice the fact that the increment here */
														/* will blow away the low-order bits doesn't matter */
			/* clear output registers */
			key_out_reg1 = key_out_reg2 = key_out_reg3 = key_out_reg4 = 0;

			for((mp &= INNER_ZERO); (mp & INNER_COUNT) < WORDSIZE; mp += INNER_ONE) {

				/* mask off first three bits and compare with rule */
				/* set the output register bit appropriately */
				key_out_reg1 |= ((rule >> (key_in_reg1 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg2 |= ((rule >> (key_in_reg2 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg3 |= ((rule >> (key_in_reg3 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg4 |= ((rule >> (key_in_reg4 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);

				/* rotate all input registers one bit to the right, preserve carry */
				mp &= LHS_ZERO;							/* clear the carry bit */
				mp |= ((key_in_reg4 & RHS_ONE) << (WORDSIZE - 1));		/* set carry bit if needed */
				key_in_reg4 >>= RHS_ONE;
				key_in_reg4 |= ((key_in_reg3 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg3 >>= RHS_ONE;
				key_in_reg3 |= ((key_in_reg2 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg2 >>= RHS_ONE;
				key_in_reg2 |= ((key_in_reg1 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg1 >>= RHS_ONE;
				key_in_reg1 |= mp & LHS_ONE;

			}

			/* now must rotate output registers one bit to the left */
			mp &= LHS_ZERO;								/* clear the carry bit */
			mp |= key_out_reg1 & LHS_ONE;						/* set the carry bit if needed */
			key_out_reg1 <<= RHS_ONE;
			key_out_reg1 |= ((key_out_reg2 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg2 <<= RHS_ONE;
			key_out_reg2 |= ((key_out_reg3 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg3 <<= RHS_ONE;
			key_out_reg3 |= ((key_out_reg4 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg4 <<= RHS_ONE;
			key_out_reg4 |=  ((mp & LHS_ONE) >> (WORDSIZE - 1));

			/* swap the input and output registers */
			key_in_reg1 = key_out_reg1;
			key_in_reg2 = key_out_reg2;
			key_in_reg3 = key_out_reg3;
			key_in_reg4 = key_out_reg4;

		}
		/* XOR right and left half together and replicate result in both key halves */
		key_in_reg1 ^= key_in_reg3;
		key_in_reg2 ^= key_in_reg4;
		key_in_reg3 = key_in_reg1;
		key_in_reg4 = key_in_reg2;
		/**************************/
		/***** END F-function *****/
		/**************************/

		/* Feistel XOR with right-half */
		key_in_reg1 ^= plain_3;
		key_in_reg2 ^= plain_4;
		key_in_reg3 = key_in_reg1;
		key_in_reg4 = key_in_reg2;
		plain_3 = key_in_reg1;
		plain_4 = key_in_reg2;

		/****************************/
		/***** START F-function *****/
		/****************************/
		/* load the third scheduled subkey */
		key_in_reg1 ^= key->key_3[0];
		key_in_reg2 ^= key->key_3[1];
		key_in_reg3 ^= key->key_3[2];
		key_in_reg4 ^= key->key_3[3];

		/* K3/CA256 */
		for((mp &= OUTER_ZERO); ((mp & OUTER_COUNT) >> DELTA_COUNT) < CA256; mp += OUTER_ONE) {		/* <-- notice the fact that the increment here */
														/* will blow away the low-order bits doesn't matter */
			/* clear output registers */
			key_out_reg1 = key_out_reg2 = key_out_reg3 = key_out_reg4 = 0;

			for((mp &= INNER_ZERO); (mp & INNER_COUNT) < WORDSIZE; mp += INNER_ONE) {

				/* mask off first three bits and compare with rule */
				/* set the output register bit appropriately */
				key_out_reg1 |= ((rule >> (key_in_reg1 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg2 |= ((rule >> (key_in_reg2 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg3 |= ((rule >> (key_in_reg3 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg4 |= ((rule >> (key_in_reg4 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);

				/* rotate all input registers one bit to the right, preserve carry */
				mp &= LHS_ZERO;							/* clear the carry bit */
				mp |= ((key_in_reg4 & RHS_ONE) << (WORDSIZE - 1));		/* set carry bit if needed */
				key_in_reg4 >>= RHS_ONE;
				key_in_reg4 |= ((key_in_reg3 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg3 >>= RHS_ONE;
				key_in_reg3 |= ((key_in_reg2 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg2 >>= RHS_ONE;
				key_in_reg2 |= ((key_in_reg1 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg1 >>= RHS_ONE;
				key_in_reg1 |= mp & LHS_ONE;

			}

			/* now must rotate output registers one bit to the left */
			mp &= LHS_ZERO;								/* clear the carry bit */
			mp |= key_out_reg1 & LHS_ONE;						/* set the carry bit if needed */
			key_out_reg1 <<= RHS_ONE;
			key_out_reg1 |= ((key_out_reg2 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg2 <<= RHS_ONE;
			key_out_reg2 |= ((key_out_reg3 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg3 <<= RHS_ONE;
			key_out_reg3 |= ((key_out_reg4 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg4 <<= RHS_ONE;
			key_out_reg4 |=  ((mp & LHS_ONE) >> (WORDSIZE - 1));

			/* swap the input and output registers */
			key_in_reg1 = key_out_reg1;
			key_in_reg2 = key_out_reg2;
			key_in_reg3 = key_out_reg3;
			key_in_reg4 = key_out_reg4;

		}
		/* XOR right and left half together and replicate result in both key halves */
		key_in_reg1 ^= key_in_reg3;
		key_in_reg2 ^= key_in_reg4;
		key_in_reg3 = key_in_reg1;
		key_in_reg4 = key_in_reg2;
		/**************************/
		/***** END F-function *****/
		/**************************/

		/* Feistel XOR with left-half */
		key_in_reg1 ^= plain_1;
		key_in_reg2 ^= plain_2;
		key_in_reg3 = key_in_reg1;
		key_in_reg4 = key_in_reg2;
		plain_1 = key_in_reg1;
		plain_2 = key_in_reg2;


		/****************************/
		/***** START F-function *****/
		/****************************/
		/* load the fourth scheduled subkey */
		key_in_reg1 ^= key->key_4[0];
		key_in_reg2 ^= key->key_4[1];
		key_in_reg3 ^= key->key_4[2];
		key_in_reg4 ^= key->key_4[3];

		/* K4/CA256 */
		for((mp &= OUTER_ZERO); ((mp & OUTER_COUNT) >> DELTA_COUNT) < CA256; mp += OUTER_ONE) {		/* <-- notice the fact that the increment here */
														/* will blow away the low-order bits doesn't matter */
			/* clear output registers */
			key_out_reg1 = key_out_reg2 = key_out_reg3 = key_out_reg4 = 0;

			for((mp &= INNER_ZERO); (mp & INNER_COUNT) < WORDSIZE; mp += INNER_ONE) {

				/* mask off first three bits and compare with rule */
				/* set the output register bit appropriately */
				key_out_reg1 |= ((rule >> (key_in_reg1 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg2 |= ((rule >> (key_in_reg2 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg3 |= ((rule >> (key_in_reg3 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg4 |= ((rule >> (key_in_reg4 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);

				/* rotate all input registers one bit to the right, preserve carry */
				mp &= LHS_ZERO;							/* clear the carry bit */
				mp |= ((key_in_reg4 & RHS_ONE) << (WORDSIZE - 1));		/* set carry bit if needed */
				key_in_reg4 >>= RHS_ONE;
				key_in_reg4 |= ((key_in_reg3 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg3 >>= RHS_ONE;
				key_in_reg3 |= ((key_in_reg2 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg2 >>= RHS_ONE;
				key_in_reg2 |= ((key_in_reg1 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg1 >>= RHS_ONE;
				key_in_reg1 |= mp & LHS_ONE;

			}

			/* now must rotate output registers one bit to the left */
			mp &= LHS_ZERO;								/* clear the carry bit */
			mp |= key_out_reg1 & LHS_ONE;						/* set the carry bit if needed */
			key_out_reg1 <<= RHS_ONE;
			key_out_reg1 |= ((key_out_reg2 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg2 <<= RHS_ONE;
			key_out_reg2 |= ((key_out_reg3 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg3 <<= RHS_ONE;
			key_out_reg3 |= ((key_out_reg4 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg4 <<= RHS_ONE;
			key_out_reg4 |=  ((mp & LHS_ONE) >> (WORDSIZE - 1));

			/* swap the input and output registers */
			key_in_reg1 = key_out_reg1;
			key_in_reg2 = key_out_reg2;
			key_in_reg3 = key_out_reg3;
			key_in_reg4 = key_out_reg4;

		}
		/* XOR right and left half together and replicate result in both key halves */
		key_in_reg1 ^= key_in_reg3;
		key_in_reg2 ^= key_in_reg4;
		key_in_reg3 = key_in_reg1;
		key_in_reg4 = key_in_reg2;
		/**************************/
		/***** END F-function *****/
		/**************************/

		/* Feistel XOR with left-half */
		key_in_reg1 ^= plain_3;
		key_in_reg2 ^= plain_4;
		key_in_reg3 = key_in_reg1;
		key_in_reg4 = key_in_reg2;
		plain_3 = key_in_reg1;
		plain_4 = key_in_reg2;


	}

	/* store the resulting ciphertext */
	*(ciphertext + 0) = plain_3;
	*(ciphertext + 1) = plain_4;
	*(ciphertext + 2) = plain_1;
	*(ciphertext + 3) = plain_2;

}


void xr30256_decrypt(struct scheduled_key *key, unsigned long int *ciphertext, unsigned long int *plaintext) {

	register unsigned long int rule = RULE30;	/* the rule to enforce */
	register unsigned long int key_in_reg1 = 0,	/* key input registers */
				   key_in_reg2 = 0,
				   key_in_reg3 = 0,
				   key_in_reg4 = 0;
	register unsigned long int key_out_reg1 = 0,	/* key output registers */
				   key_out_reg2 = 0,
				   key_out_reg3 = 0,
				   key_out_reg4 = 0;
	register unsigned long int cipher_1 = 0,
				   cipher_2 = 0,
				   cipher_3 = 0,
				   cipher_4 = 0;
	register unsigned long int key_carry = 0;	/* used to perform key rotation */
	register unsigned long int mp = 0;		/* multi-purpose register:					*/
							/* 	- the right-most 8 bits are for the inner loop counter	*/
							/* 	- the next 16 bits are for the outer loop counter	*/
							/*	- the next 16 bits are for the rounds counter		*/
							/* 	- the left-most bit is for carries			*/

	/* load the ciphertext */
	cipher_1 = *(ciphertext + 0);
	cipher_2 = *(ciphertext + 1);
	cipher_3 = *(ciphertext + 2);
	cipher_4 = *(ciphertext + 3);

	/* initialize with the right-half */
	key_in_reg1 ^= cipher_3;
	key_in_reg2 ^= cipher_4;
	key_in_reg3 = key_in_reg1;
	key_in_reg4 = key_in_reg2;

	for(mp &= ROUNDS_ZERO; ((mp & ROUNDS_COUNT) >> DELTA_ROUNDS) < ROUNDS; mp += ROUNDS_ONE) {

		/****************************/
		/***** START F-function *****/
		/****************************/
		/* load the fourth scheduled subkey */
		key_in_reg1 ^= key->key_4[0];
		key_in_reg2 ^= key->key_4[1];
		key_in_reg3 ^= key->key_4[2];
		key_in_reg4 ^= key->key_4[3];

		/* K4/CA256 */
		for((mp &= OUTER_ZERO); ((mp & OUTER_COUNT) >> DELTA_COUNT) < CA256; mp += OUTER_ONE) {		/* <-- notice the fact that the increment here */
														/* will blow away the low-order bits doesn't matter */
			/* clear output registers */
			key_out_reg1 = key_out_reg2 = key_out_reg3 = key_out_reg4 = 0;

			for((mp &= INNER_ZERO); (mp & INNER_COUNT) < WORDSIZE; mp += INNER_ONE) {

				/* mask off first three bits and compare with rule */
				/* set the output register bit appropriately */
				key_out_reg1 |= ((rule >> (key_in_reg1 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg2 |= ((rule >> (key_in_reg2 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg3 |= ((rule >> (key_in_reg3 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg4 |= ((rule >> (key_in_reg4 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);

				/* rotate all input registers one bit to the right, preserve carry */
				mp &= LHS_ZERO;							/* clear the carry bit */
				mp |= ((key_in_reg4 & RHS_ONE) << (WORDSIZE - 1));		/* set carry bit if needed */
				key_in_reg4 >>= RHS_ONE;
				key_in_reg4 |= ((key_in_reg3 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg3 >>= RHS_ONE;
				key_in_reg3 |= ((key_in_reg2 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg2 >>= RHS_ONE;
				key_in_reg2 |= ((key_in_reg1 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg1 >>= RHS_ONE;
				key_in_reg1 |= mp & LHS_ONE;

			}

			/* now must rotate output registers one bit to the left */
			mp &= LHS_ZERO;								/* clear the carry bit */
			mp |= key_out_reg1 & LHS_ONE;						/* set the carry bit if needed */
			key_out_reg1 <<= RHS_ONE;
			key_out_reg1 |= ((key_out_reg2 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg2 <<= RHS_ONE;
			key_out_reg2 |= ((key_out_reg3 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg3 <<= RHS_ONE;
			key_out_reg3 |= ((key_out_reg4 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg4 <<= RHS_ONE;
			key_out_reg4 |=  ((mp & LHS_ONE) >> (WORDSIZE - 1));

			/* swap the input and output registers */
			key_in_reg1 = key_out_reg1;
			key_in_reg2 = key_out_reg2;
			key_in_reg3 = key_out_reg3;
			key_in_reg4 = key_out_reg4;

		}

		/* XOR right and left half together and replicate result in both key halves */
		key_in_reg1 ^= key_in_reg3;
		key_in_reg2 ^= key_in_reg4;
		key_in_reg3 = key_in_reg1;
		key_in_reg4 = key_in_reg2;
		/**************************/
		/***** END F-function *****/
		/**************************/

		/* Feistel XOR with left-half */
		key_in_reg1 ^= cipher_1;
		key_in_reg2 ^= cipher_2;
		key_in_reg3 = key_in_reg1;
		key_in_reg4 = key_in_reg2;
		cipher_1 = key_in_reg1;
		cipher_2 = key_in_reg2;

		/****************************/
		/***** START F-function *****/
		/****************************/
		/* load the third scheduled subkey */
		key_in_reg1 ^= key->key_3[0];
		key_in_reg2 ^= key->key_3[1];
		key_in_reg3 ^= key->key_3[2];
		key_in_reg4 ^= key->key_3[3];

		/* K3/CA256 */
		for((mp &= OUTER_ZERO); ((mp & OUTER_COUNT) >> DELTA_COUNT) < CA256; mp += OUTER_ONE) {		/* <-- notice the fact that the increment here */
														/* will blow away the low-order bits doesn't matter */
			/* clear output registers */
			key_out_reg1 = key_out_reg2 = key_out_reg3 = key_out_reg4 = 0;

			for((mp &= INNER_ZERO); (mp & INNER_COUNT) < WORDSIZE; mp += INNER_ONE) {

				/* mask off first three bits and compare with rule */
				/* set the output register bit appropriately */
				key_out_reg1 |= ((rule >> (key_in_reg1 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg2 |= ((rule >> (key_in_reg2 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg3 |= ((rule >> (key_in_reg3 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg4 |= ((rule >> (key_in_reg4 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);

				/* rotate all input registers one bit to the right, preserve carry */
				mp &= LHS_ZERO;							/* clear the carry bit */
				mp |= ((key_in_reg4 & RHS_ONE) << (WORDSIZE - 1));		/* set carry bit if needed */
				key_in_reg4 >>= RHS_ONE;
				key_in_reg4 |= ((key_in_reg3 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg3 >>= RHS_ONE;
				key_in_reg3 |= ((key_in_reg2 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg2 >>= RHS_ONE;
				key_in_reg2 |= ((key_in_reg1 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg1 >>= RHS_ONE;
				key_in_reg1 |= mp & LHS_ONE;

			}

			/* now must rotate output registers one bit to the left */
			mp &= LHS_ZERO;								/* clear the carry bit */
			mp |= key_out_reg1 & LHS_ONE;						/* set the carry bit if needed */
			key_out_reg1 <<= RHS_ONE;
			key_out_reg1 |= ((key_out_reg2 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg2 <<= RHS_ONE;
			key_out_reg2 |= ((key_out_reg3 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg3 <<= RHS_ONE;
			key_out_reg3 |= ((key_out_reg4 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg4 <<= RHS_ONE;
			key_out_reg4 |=  ((mp & LHS_ONE) >> (WORDSIZE - 1));

			/* swap the input and output registers */
			key_in_reg1 = key_out_reg1;
			key_in_reg2 = key_out_reg2;
			key_in_reg3 = key_out_reg3;
			key_in_reg4 = key_out_reg4;

		}
		/* XOR right and left half together and replicate result in both key halves */
		key_in_reg1 ^= key_in_reg3;
		key_in_reg2 ^= key_in_reg4;
		key_in_reg3 = key_in_reg1;
		key_in_reg4 = key_in_reg2;
		/**************************/
		/***** END F-function *****/
		/**************************/

		/* Feistel XOR with right-half */
		key_in_reg1 ^= cipher_3;
		key_in_reg2 ^= cipher_4;
		key_in_reg3 = key_in_reg1;
		key_in_reg4 = key_in_reg2;
		cipher_3 = key_in_reg1;
		cipher_4 = key_in_reg2;


		/****************************/
		/***** START F-function *****/
		/****************************/
		/* load the second scheduled subkey */
		key_in_reg1 ^= key->key_2[0];
		key_in_reg2 ^= key->key_2[1];
		key_in_reg3 ^= key->key_2[2];
		key_in_reg4 ^= key->key_2[3];

		/* K2/CA256 */
		for((mp &= OUTER_ZERO); ((mp & OUTER_COUNT) >> DELTA_COUNT) < CA256; mp += OUTER_ONE) {		/* <-- notice the fact that the increment here */
														/* will blow away the low-order bits doesn't matter */
			/* clear output registers */
			key_out_reg1 = key_out_reg2 = key_out_reg3 = key_out_reg4 = 0;

			for((mp &= INNER_ZERO); (mp & INNER_COUNT) < WORDSIZE; mp += INNER_ONE) {

				/* mask off first three bits and compare with rule */
				/* set the output register bit appropriately */
				key_out_reg1 |= ((rule >> (key_in_reg1 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg2 |= ((rule >> (key_in_reg2 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg3 |= ((rule >> (key_in_reg3 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg4 |= ((rule >> (key_in_reg4 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);

				/* rotate all input registers one bit to the right, preserve carry */
				mp &= LHS_ZERO;							/* clear the carry bit */
				mp |= ((key_in_reg4 & RHS_ONE) << (WORDSIZE - 1));		/* set carry bit if needed */
				key_in_reg4 >>= RHS_ONE;
				key_in_reg4 |= ((key_in_reg3 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg3 >>= RHS_ONE;
				key_in_reg3 |= ((key_in_reg2 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg2 >>= RHS_ONE;
				key_in_reg2 |= ((key_in_reg1 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg1 >>= RHS_ONE;
				key_in_reg1 |= mp & LHS_ONE;

			}

			/* now must rotate output registers one bit to the left */
			mp &= LHS_ZERO;								/* clear the carry bit */
			mp |= key_out_reg1 & LHS_ONE;						/* set the carry bit if needed */
			key_out_reg1 <<= RHS_ONE;
			key_out_reg1 |= ((key_out_reg2 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg2 <<= RHS_ONE;
			key_out_reg2 |= ((key_out_reg3 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg3 <<= RHS_ONE;
			key_out_reg3 |= ((key_out_reg4 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg4 <<= RHS_ONE;
			key_out_reg4 |=  ((mp & LHS_ONE) >> (WORDSIZE - 1));

			/* swap the input and output registers */
			key_in_reg1 = key_out_reg1;
			key_in_reg2 = key_out_reg2;
			key_in_reg3 = key_out_reg3;
			key_in_reg4 = key_out_reg4;

		}
		/* XOR right and left half together and replicate result in both key halves */
		key_in_reg1 ^= key_in_reg3;
		key_in_reg2 ^= key_in_reg4;
		key_in_reg3 = key_in_reg1;
		key_in_reg4 = key_in_reg2;
		/**************************/
		/***** END F-function *****/
		/**************************/

		/* Feistel XOR with left-half */
		key_in_reg1 ^= cipher_1;
		key_in_reg2 ^= cipher_2;
		key_in_reg3 = key_in_reg1;
		key_in_reg4 = key_in_reg2;
		cipher_1 = key_in_reg1;
		cipher_2 = key_in_reg2;


		/****************************/
		/***** START F-function *****/
		/****************************/
		/* load the first scheduled subkey */
		key_in_reg1 ^= key->key_1[0];
		key_in_reg2 ^= key->key_1[1];
		key_in_reg3 ^= key->key_1[2];
		key_in_reg4 ^= key->key_1[3];

		/* K1/CA256 */
		for((mp &= OUTER_ZERO); ((mp & OUTER_COUNT) >> DELTA_COUNT) < CA256; mp += OUTER_ONE) {		/* <-- notice the fact that the increment here */
														/* will blow away the low-order bits doesn't matter */
			/* clear output registers */
			key_out_reg1 = key_out_reg2 = key_out_reg3 = key_out_reg4 = 0;

			for((mp &= INNER_ZERO); (mp & INNER_COUNT) < WORDSIZE; mp += INNER_ONE) {

				/* mask off first three bits and compare with rule */
				/* set the output register bit appropriately */
				key_out_reg1 |= ((rule >> (key_in_reg1 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg2 |= ((rule >> (key_in_reg2 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg3 |= ((rule >> (key_in_reg3 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);
				key_out_reg4 |= ((rule >> (key_in_reg4 & CELL_MASK)) & RHS_ONE) << (mp & INNER_COUNT);

				/* rotate all input registers one bit to the right, preserve carry */
				mp &= LHS_ZERO;							/* clear the carry bit */
				mp |= ((key_in_reg4 & RHS_ONE) << (WORDSIZE - 1));		/* set carry bit if needed */
				key_in_reg4 >>= RHS_ONE;
				key_in_reg4 |= ((key_in_reg3 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg3 >>= RHS_ONE;
				key_in_reg3 |= ((key_in_reg2 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg2 >>= RHS_ONE;
				key_in_reg2 |= ((key_in_reg1 & RHS_ONE) << (WORDSIZE - 1));
				key_in_reg1 >>= RHS_ONE;
				key_in_reg1 |= mp & LHS_ONE;

			}

			/* now must rotate output registers one bit to the left */
			mp &= LHS_ZERO;								/* clear the carry bit */
			mp |= key_out_reg1 & LHS_ONE;						/* set the carry bit if needed */
			key_out_reg1 <<= RHS_ONE;
			key_out_reg1 |= ((key_out_reg2 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg2 <<= RHS_ONE;
			key_out_reg2 |= ((key_out_reg3 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg3 <<= RHS_ONE;
			key_out_reg3 |= ((key_out_reg4 & LHS_ONE) >> (WORDSIZE - 1));
			key_out_reg4 <<= RHS_ONE;
			key_out_reg4 |=  ((mp & LHS_ONE) >> (WORDSIZE - 1));

			/* swap the input and output registers */
			key_in_reg1 = key_out_reg1;
			key_in_reg2 = key_out_reg2;
			key_in_reg3 = key_out_reg3;
			key_in_reg4 = key_out_reg4;

		}
		/* XOR right and left half together and replicate result in both key halves */
		key_in_reg1 ^= key_in_reg3;
		key_in_reg2 ^= key_in_reg4;
		key_in_reg3 = key_in_reg1;
		key_in_reg4 = key_in_reg2;
		/**************************/
		/***** END F-function *****/
		/**************************/

		/* Feistel XOR with left-half */
		key_in_reg1 ^= cipher_3;
		key_in_reg2 ^= cipher_4;
		key_in_reg3 = key_in_reg1;
		key_in_reg4 = key_in_reg2;
		cipher_3 = key_in_reg1;
		cipher_4 = key_in_reg2;


	}

	/* store the resulting ciphertext */
	*(plaintext + 0) = cipher_3;
	*(plaintext + 1) = cipher_4;
	*(plaintext + 2) = cipher_1;
	*(plaintext + 3) = cipher_2;

}

#else /* 32-bit */

#endif /* WORDSIZE == 64 */

int main() {

	int i;
	unsigned long int key[4];
	struct scheduled_key *skey;
	unsigned long int plaintext[4];
	unsigned long int ciphertext[4];
	clock_t time_initial, time_final;

	key[0] = 0xa59535d07e192f12;
	key[1] = 0x82734fb3084c5e05;
	key[2] = 0x385b8a038d28e669;
	key[3] = 0xd2bc44a82c395d8e;

	plaintext[0] = 0x0101010101010101;
	plaintext[1] = 0x0202020202020202;
	plaintext[2] = 0x0303030303030303;
	plaintext[3] = 0x0404040404040404;

	ciphertext[0] = 0x0000000000000000;
	ciphertext[1] = 0x0000000000000000;
	ciphertext[2] = 0x0000000000000000;
	ciphertext[3] = 0x0000000000000000;

	skey = xr30256_key_schedule(key);

#ifdef DEBUG
	printf("before encryption:\n");
	printf("key:\n"); print_binary(key[0]); print_binary(key[1]); print_binary(key[2]); print_binary(key[3]); printf("\n");
	printf("plaintext:\n"); print_binary(plaintext[0]); print_binary(plaintext[1]); print_binary(plaintext[2]); print_binary(plaintext[3]); printf("\n");

	xr30256_encrypt(skey, plaintext, ciphertext);

	printf("after encryption:\n");
	printf("ciphertext:\n"); print_binary(ciphertext[0]); print_binary(ciphertext[1]); print_binary(ciphertext[2]); print_binary(ciphertext[3]); printf("\n");

	plaintext[0] = plaintext[1] = plaintext[2] = plaintext[3] = 0;

	xr30256_decrypt(skey, ciphertext, plaintext);

	printf("after decryption:\n");
	printf("plaintext:\n"); print_binary(plaintext[0]); print_binary(plaintext[1]); print_binary(plaintext[2]); print_binary(plaintext[3]); printf("\n");
#endif /* DEBUG */

#ifdef BENCHMARK
	while(1) {
		time_initial = time_final = clock();
		for(i = 0; (time_final - time_initial)/CLOCKS_PER_SEC < 1.0; i++) {
			xr30256_encrypt(skey, plaintext, ciphertext);
			time_final = clock();
		}

		printf("%d encryptions/sec\n", i);
	}
#endif /* BENCHMARK */

	free(skey);
	exit(0);

}


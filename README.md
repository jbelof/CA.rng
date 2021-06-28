# CA.rng

Cellular automata (CA) are a class of discrete algorithms that, despite their simplicity, exhibit considerable complexity.  Some CAs appear to represent physical phenomena, others display nothing interesting whatsoever.  The general trend, however, is that the self-interaction and non-linearity of CAs results in emergent behavior.  Other well known examples are Conway's "Game of Life" and the lattice-boltzmann formulation of hydrodynamics.

CA.rng is a set of utilities that implement a general computational framework for CAs by bitwise arithmetic.  The binary logic is encoded such that the compiler will load and operate in register space, for high performance applications.

Three CA utilies are included: (1) a general CA code that outputs the bitstream for display, (2) a pseudo-random number generator and (3) a toy crypographic cipher based on a 256-bit CA to serve as the S-box in a Feistel network .  All examples apply the "rule 30" CA for demonstration.


## Installing

Compilation is simple and relies on only standard libraries.  Please consult the source code for the specific utility for details.


## Running the examples

Running the generic code "rule30.c" gives visual output of the self-organization pattern of triangles that is well known with the rule 30 CA:

$ ./r30

...


The example code "rule30.rng.c" outputs a stream of pseudo random numbers to stdout.  For convenience of verifying randomness, a small code to calculate the autocorrelation function for a sequence S, <S(t)S(t')>, is included.

Finally, a toy symmetric block cipher, XR30256, is included in the code "rule30.crypt.c".  This cipher implements a 16 round Feistel network using an F-function that consists of CA256 (4 iterations of the rule 30 CA with cyclic boundary conditions).  The input to the F function is initially the right or left plaintext block of length 128 bits expanded to 256 and then XOR'd with the subkey before running through the CA.  The key scheduler is a 4-part decomposition.


## Authors

* **Jon Belof** [jbelof@github](https://github.com/jbelof)  

[home page](http://people.llnl.gov/belof1)  
[google scholar](https://scholar.google.com/citations?user=gNrlNbwAAAAJ&hl=en)  
[research gate](https://www.researchgate.net/profile/Jon_Belof)  
[linkedin](http://www.linkedin.com/in/jbelof)  
[web profile](https://llnl.academia.edu/jonathanbelof)  


## License

This project is licensed under the GNU General Public License v3, please see GPL_license.txt for details.



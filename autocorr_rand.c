/****************************************************************************************/
/* Determines the correlation time interval for a random sequence			*/
/*											*/
/* The input signal is specified in an input file where each line holds a single	*/
/* floating point value.  The signal values are all shifted by the average value in	*/
/* order that the signal may fluctuate about the x-axis.  The normalization constant is	*/
/* then calculated so that the autocorrelation function will return values from 0.0	*/
/* to 1.0.  A random signal will see a rapid decay time, whereas a signal with greater	*/
/* periodicity would be evident by judging decay time until crossing the x-axis, thus	*/
/* determining the correlation interval.						*/
/*											*/
/* This implmentation utilizes the autocorrelation function as follows.  The j-th value	*/
/* of the autocorrelation function (in latex) is given by:				*/
/*											*/
/*			\sum_i^{\frac{N}{2}} s(j)*s(i+j)				*/
/*											*/
/* where s(k) is the value of the signal at time k and N is the total number of data	*/
/* points in the signal.  The autocorrelation function is then described by generating	*/
/* output for all j's up to N/2.  The average of this sum is then taken by dividing by	*/
/* the number of points processed (N/2) and a normalization constant, where the		*/
/* normalization constant is given by:							*/
/*											*/
/*				 \sum_i^N s(i)^2					*/
/*											*/
/* References:										*/
/*	Mitra, "Digital Signal Processing"						*/
/*	Frenkel, "Understanding Molecular Simulation"					*/
/*											*/
/* @2005 Jonathan Belof									*/
/****************************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include <time.h>

#define NUM_LINES		4000000



void autocorr(double *dat, int num) {

	double avg = 0;
	double norm = 0;
	double vac = 0;
	int i, j;

	/* calculate the correlated average */
	for(i = 0; i < num; i++) {
		avg += *(dat + i);
	}
	avg /= num;
	printf("# correlated average = %f\n", avg);

	/* shift the data set to fluctuate about the average */
	for(i = 0; i < num; i++)
		*(dat + i) -=avg;

	/* calculate the normalization constant */
	for(i = 0; i < num; i++) {
		norm += *(dat + i)*(*(dat + i));
	}
	norm /= num;
	printf("# normalization constant = %f\n", norm);

	/* autocorrelate the signal across half of the domain, ensuring data point quality */
	for(i = 0; i < (num / 2); i++) {
		vac = 0;
		for(j = 0; j < (num / 2); j++) {
			vac += *(dat + j)*(*(dat + i + j));
		}

		/* normalize the autocorrelation from 0 to 1 */
		vac /= (num / 2)*norm;
		printf("%d %f\n", i, vac);
	}

}

void usage(char *progname) {

	fprintf(stderr, "usage: %s [datafile]\n", progname);
	exit(1);

}

int main(int argc, char **argv) {

        int i, n = 0;
	char *datfile;
	FILE *fp;
	double *dat;

        if(argc < 2) usage((char *)argv[0]);

	datfile = argv[1];
	if(!datfile) {
		fprintf(stderr, "datfile not specified\n");
		usage((char *)argv[0]);
	}
	else
		fp = fopen(datfile, "r");

	if(!fp) {
		fprintf(stderr, "%s not found\n", datfile);
		usage((char *)argv[0]);
	}

	/* load in the data  - XXX do without num_lines */
        dat = (double *)calloc(NUM_LINES, sizeof(double));
        if(!dat) {
                fprintf(stderr, "couldn't allocate working memory buffer\n");
                exit(1);
        }

        for(i = 0; n != EOF; i++) {
                n = fscanf(fp, "%lg", (dat + i));
        }
        fclose(fp);


	autocorr(dat, i);

	free(dat);
	exit(0);

}


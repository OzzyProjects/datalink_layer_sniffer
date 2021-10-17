#ifndef RANDOM_H
#define RANDOM_H

/* Determine what type to use based on Perl's detection */
#ifdef USE_INT
typedef  unsigned int  ub4;
#else
typedef  unsigned long  ub4;
#endif

#ifndef UINT32_MAX
#define UINT32_MAX (4294967295U)
#endif

/* Some miscellaneous bit operation macros */
#define bis(target,mask)  ((target) |=  (mask))
#define bic(target,mask)  ((target) &= ~(mask))
#define bit(target,mask)  ((target) &   (mask))

/* Find the minimum of two values */
#ifndef min
#define min(a,b) (((a)<(b)) ? (a) : (b))
#endif /* min */

/* Find the maximum of two values */
#ifndef max
#define max(a,b) (((a)<(b)) ? (b) : (a))
#endif /* max */

#ifndef align
#define align(a) (((ub4)a+(sizeof(void *)-1))&(~(sizeof(void *)-1)))
#endif /* align */

/* Some boolean truth value constants */
#ifndef TRUE
#define TRUE  1
#endif /* TRUE */
#ifndef FALSE
#define FALSE 0
#endif /* FALSE */

#ifndef RAND_H
#define RAND_H 1
#endif

#define RANDSIZL  (8)  /* 8 for crypto, 4 for simulations */
#define RANDSIZ   (1 << RANDSIZL)

/* context of random number generator */
struct randctx {

  ub4 randcnt;
  ub4 randrsl[RANDSIZ];
  ub4 randmem[RANDSIZ];
  ub4 randa;
  ub4 randb;
  ub4 randc;
};

typedef  struct randctx  randctx;

/* Initialize using randrsl[0..RANDSIZ-1] as the seed */
void randinit(randctx *);
static void isaac(randctx *);
ub4 randInt(randctx *);

#endif
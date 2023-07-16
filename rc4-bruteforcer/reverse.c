#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <libproc.h>

#define MONTH_START         1
#define MONTH_END           12
#define N_THREADS           MONTH_END - MONTH_START + 1
#define DAY_START           1
#define DAY_END             31
#define HOUR_START          0
#define HOUR_END            23
#define MAJOR_VERSION_START 5
#define MAJOR_VERSION_END   11
#define MINOR_VERSION_START 0
#define MINOR_VERSION_END   3
#define DEBUG_START         0
#define DEBUG_END           1
#define LANGUAGE_START      0
#define LANGUAGE_END        147

#ifdef DEBUG
  #define DBG(...) printf(__VA_ARGS__)
#else
  #define DBG(...)
#endif

unsigned char enc[35] = {0xa6, 0xcb, 0x8d, 0xc9, 0x70, 0x96, 0xd1, 0x71, 0x6f,
			 0x97, 0x66, 0xa7, 0x9d, 0xa6, 0x24, 0x61, 0xd6, 0xea,
			 0x5e, 0x82, 0xeb, 0xdb, 0x1e, 0x22, 0xa5, 0x4f, 0xf6,
			 0x02, 0x86, 0x97, 0x1c, 0x6c, 0x01, 0xb8, 0x00};

typedef struct {
  int month;
  int exit_early;
} DECRYPT_ARGS;

void *decyrpt(void *arg);

void *decrypt(void *arg)
{
  DECRYPT_ARGS *dcarg;

  unsigned char dec[35]; /* Decoded message */
  unsigned char xtab[256]; /* Translation table */

  unsigned char key[11] = {
    0x62, /* key[0] = 'b' */
    0x30, /* key[1] = '0' */
    0x30, /* key[2] = '0' */
    0x21, /* key[3] = '!' */
    0x00, /* key[4] = lb(0x35 + localtime[2]{Month}) */
    0x00, /* key[5] = lb(0x29 + localtime[6]{DayofMonth}) */
    0x00, /* key[6] = lb(0x40 + localtime[8]{Hour}) */
    0x00, /* key[7] = 0x73 + lb(GetVersion()) [5-10] */
    0x00, /* key[8] = 0x5d + hb(GetVersion()) [0-3]*/
    0x00, /* key[9] = 0x3f + PEB[BeingDebugged] [0 or 1] */
    0x00 /* key[10] -- set to hb(Language) + 0x6b [0..255] */
  };

  short i, j;
  short byte1, byte2, bytetmp;

  int month, day, hour, vhigh, vlow, debug, lang;

  dcarg = arg;

  month = dcarg->month;

  for (day = DAY_START; day <= DAY_END; day++)
    for (hour = HOUR_START; hour <= HOUR_END; hour++)
      for (vhigh = MAJOR_VERSION_START; vhigh <= MAJOR_VERSION_END; vhigh++)
	for (vlow = MINOR_VERSION_START; vlow <= MINOR_VERSION_END; vlow++)
	  for (debug = DEBUG_START; debug <= DEBUG_END; debug++)
	    for (lang = LANGUAGE_START; lang <= LANGUAGE_END; lang++) {
	      key[4] = 0x35 + month;
	      key[5] = 0x29 + day;
	      key[6] = 0x40 + hour;
	      key[7] = 0x73 + vhigh;
	      key[8] = 0x5d + vlow;
	      key[9] = 0x3f + debug;
	      key[10] = (0x6b + lang) & 0xff;

	      /* Build table */
	      for (i = 0; i < 256; i++)
		xtab[i] = i;

	      /* Transform table */
	      for (i = 0, j = 0, byte2 = 0; i < 256; i++) {
		byte1 = xtab[i];

		byte2 = (byte1 + byte2 + key[j]) & 0xff;

		DBG ("DBG %02x %02x ", byte1, byte2);

		xtab[i] = xtab[byte2];
		xtab[byte2] = byte1;

		DBG ("%02x %02x\n", xtab[i], xtab[byte2]);

		j++;
		if (j >= 11)
		  j = 0;
	      }

	      /* Decrypt message */
	      for (i = 1, j = 0, byte1 = 0, byte2 = 0, bytetmp = 0; i < 34;
		   i++) {
		byte1 = xtab[i];

		j = (j + byte1) & 0xff;

	        byte2 = xtab[j];

		xtab[i] = byte2;
		xtab[j] = byte1;

		/* Mask to match add bl, dl */
		bytetmp = xtab[(byte1 + byte2)&0xff];

		dec[i - 1] = bytetmp ^ enc[i - 1];
	      }
	      dec[34] = '\0';

	      if (!strncmp((char *)&dec, "Key:", 4)) {
		printf ("Possible key: %s\n", dec);
		printf ("\tMonth: %d Day: %d Hour: %d MajVersion: %d " \
			"MinVersion: %d PEB[BeingDebugged]: %d Language: %d\n",
			month, day, hour, vhigh, vlow, debug, lang);
		if (dcarg->exit_early)
		  exit(1);
	      }
	    }
  pthread_exit(NULL);
}

int main (int argc, char **argv)
{
  pthread_t pt[N_THREADS];
  DECRYPT_ARGS dcargs[N_THREADS];

  int i, rc;

  //proc_set_no_smt();
  
  for (i = 0; i < N_THREADS; i++) {
    dcargs[i].month = MONTH_START + i;

    if (argc > 1 && !strncmp(argv[1], "-exit", strlen(argv[1])))
      dcargs[i].exit_early = 1;
    else
      dcargs[i].exit_early = 0;

    rc = pthread_create(&pt[i], NULL, decrypt, &dcargs[i]);

    if (rc == -1) {
      fprintf (stderr, "Could not create thread idx %d: %s\n", i,
	       strerror(errno));
      exit (1);
    }
  }

  /* Wait for threads to finish */
  for (i = 0; i < N_THREADS; i++)
    pthread_join(pt[i], NULL);
}

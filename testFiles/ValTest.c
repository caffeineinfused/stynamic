/*
 * =====================================================================================
 *
 *       Filename:  ValTest.c
 *
 *    Description:  Testing file for Valgrind wrapper class
 *
 *        Version:  1.0
 *        Created:  03/28/2017 11:32:46 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Zackary Foreman 
 *   Organization:  University of Colorado Denver, Undergraduate 
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

void OverRun(void)
{
	int* x = (int *)malloc(10*sizeof(int));
	x[10] = 0;
}

void randStringGen(int x, char* c)
{
	srand(time(NULL));
	for(int I = 0; I < x-1; ++I)
	{
		*c = 'A'+(rand()%26);
		c++;
	}
	*c='\0';
}

void bufferUnder(void)
{
	char buffer[256];
	char* c = (char *)malloc(255*sizeof(char));
	randStringGen(255, c);
	strcpy(buffer, c);
	printf("%s\n",buffer);
	free(c);
}

void danglingPtr(void)
{
	int *x;
	int * y = (int *)malloc(10*sizeof(int));
	x = y;
	free(y);
	int t = x[2];
}


void unInitializedPtr(void)
{
	char *buffer;
	char* c = (char *)malloc(10*sizeof(char));
	randStringGen(10, c);
	strcpy(buffer, c);
	printf("%s\n", buffer);
	free(c);
	free(buffer);
}

void bufferOver(void)
{
	char buffer[256];
	char* c = (char *)malloc(260*sizeof(char));
	randStringGen(260, c);
	strcpy(buffer, c);
	printf("%s\n", buffer);
	free(c);
}

int main(int argc, char**argv)
{
	if(argc != 2)
	{
		return 0;
	}
	int x = (int)(argv[1][0]-'0');
	if(x == 1)
	{
		OverRun();
		printf("overrun");
		return 0;
	}
	else if(x == 2)
	{
		unInitializedPtr();
		return 0;
	}
	else if(x ==3)
	{
		danglingPtr();
		return 0;
	}
	else if(x ==4)
	{
		bufferUnder();
		return 0;
	}
	else
	{
		bufferOver();
		return 0;
	}
}

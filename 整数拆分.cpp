
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void DY(int sumStack[], int top, int n, int initN);
void reverse(int numStack[], int sumStack[], int numtop, int sumtop, int n, int nn);
#define MAX_INTEGER			20
int temp = 0;
/*
整数拆分：输入一个1--20之间的整数，将其拆分成多个整数的和
例如：
5 = 1 + 1 + 1 + 1 + 1  4=1+1+1+1     7=1+1+1+1+1+1+1
5 = 2 + 1 + 1 + 1      4=2+1+1       7=2+1+1+1+1+1
5 = 2 + 2 + 1          4=2+2         7=2+2+1+1+1
5 = 3 + 1 + 1          4=3+1         7=2+2+2+1
5 = 3 + 2              4=4           7=3+1+1+1+1
5 = 4 + 1                            7=3+2+1+1
5 = 5                                7=3+2+2
									7=3+3+1
									7=4+1+1+1
									7=4+2+1
									7=4+3
									7=5+1+1
									7=5+2
									7=6+1
									7=7
*/
int main()
{
	//整数拆分时需要用到的堆栈
	int				sumStack[MAX_INTEGER]; //各个加数的和的堆栈
	int				numStack[MAX_INTEGER]; //各个加数的堆栈
	int				top; //栈顶
	int				nn;
	int				ii;
	while (1 == 1)
	{
		for (ii = 0; ii < MAX_INTEGER; ii++)
		{
			sumStack[ii] = 0;
			numStack[ii] = 0;
		}
		top = 0;
		nn = 0;
		//prt = " ";
		printf("nn = ");
		scanf("%d", &nn);
		if ((nn < 1) || (nn > MAX_INTEGER))
			return 1;
		else {

			for (int i = 0; i < nn; i++)
				numStack[top++] = 1;
		}
		reverse(numStack, sumStack, top - 1, 0, nn, nn);
		//DY(sumStack, top, nn, 1);

		printf("end\n");
	}
	return 0;
}

void reverse(int numStack[], int sumStack[], int numtop, int sumtop, int n, int nn)
{
	

	if (numtop==0 && n <= 1)
	{
		return;
	}


	for (int i = 2; i <= nn; i++)
	{

		numtop = numtop - i;
		
		sumStack[sumtop++] = i;

		for (int j = numtop; j >= 0; j--)
		{
			sumStack[sumtop++] = 1;
		}

		for (int k = 0; k < sumtop; k++)
		{
			printf("%d\t", sumStack[k]);
		}
		printf("\n");

		if (numtop == -1)
		{
			for (int j = 0; j < sumtop; j++)
				if (sumStack[j] == i)
					temp++;
			sumtop = sumtop - temp ;
			i++;
		}
		else {
			sumtop = sumtop - numtop - 1;
		}
		
		reverse(numStack, sumStack, numtop, sumtop, n - i, nn);
		numtop = nn - 1;
		sumtop = 0;
		n = nn;
	}

}

/*
void DY(int sumStack[], int top, int n, int initN)
{
	if (n <= 0)
	{
		for (int i = 0; i < top; i++)
			printf("%d", sumStack[i]);
		printf("\n");
	}
	for (int i = initN; i <= n; i++)
	{
		sumStack[top] = i;
		top++;
		DY(sumStack, top, n - i, i);
		top--;
	}
}
*/

/*

char Dy(int numStack[], int sumStack[], int stacktop)
{
	int sumtop = 0;
	int temp = 0;
	if (stacktop <= 1)
	{
		return;
	}
	for (int i = 2; i <= stacktop; i++)
	{
		if (i > 2)
		{
			sumStack[sumtop] = i;
			temp = stacktop - i;
			for (int j = temp; j >= 0; j--)
				sumStack[++sumtop] = numStack[j];
			for (int k = 2; k <= i; k++)
			{
				for (int m = 1; m < 10; m++)
				{
					if (stacktop - k * m > -1)
					{
						temp = stacktop - i - k * m;
						sumStack[sumtop] = i;
						for (; m > 0; m--)
							sumStack[++sumtop] = k;
						for (int j = temp; j >= 0; j--)
							sumStack[++sumtop] = numStack[j];
					}
				}
			}




			if (stacktop - i - 2 > -1)
				sumStack[sumtop++] = 2;
			temp = stacktop - i - 2;
			for (int j = temp; j >= 0; j--)
				sumStack[++sumtop] = numStack[j];


			if(stacktop-i-2*2>-1)



		}
		else {
			sumStack[sumtop] = i;
			temp = stacktop - i;
			for (int j = temp; j >= 0; j--)

				sumStack[++sumtop] = numStack[j];
		}

	}


}

*/

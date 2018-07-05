
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INTEGER			20
//void reverse(int sumStack[], int top, int n, int ii);
int temp;
void Func(int sumstack[], int n, int i, int top);
/*
整数拆分：输入一个1--20之间的整数，将其拆分成多个整数的和
例如：
5 = 1 + 1 + 1 + 1 + 1
5 = 2 + 1 + 1 + 1
5 = 2 + 2 + 1
5 = 3 + 1 + 1
5 = 3 + 2
5 = 4 + 1
5 = 5
*/
int main()
{
	//整数拆分时需要用到的堆栈
	int				sumStack[MAX_INTEGER]; //各个加数的和的堆栈
	int				numStack[MAX_INTEGER]; //各个加数的堆栈
	int				top; //栈顶
	int				nn;
	int				ii;
	int             n;
	while (1 == 1)
	{
		for (ii = 0; ii < MAX_INTEGER; ii++)
		{
			sumStack[ii] = 0;
			numStack[ii] = 0;
		}
		top = 0;
		nn = 0;
		printf("nn = ");
		scanf("%d", &nn);
		temp = nn;
		if ((nn < 1) || (nn > MAX_INTEGER))
			return 1;
		else {
			for (int i = 0; i < nn; i++)
				numStack[i] = 1;
		}
		/*	for (ii = 2; ii <= nn; ii++)
			{
				top = 0;
				sumStack[top++] = ii;
				n = nn - ii;

			//	reverse(sumStack, top, n, ii);
			}
			*/

		for (int i = 1; i <= nn; i++)
		{
			Func(sumStack, nn, i, top);
		}


		printf("end\n");
	}
	return 0;
}


/////////////////////////////

/*
void reverse(int sumStack[], int top, int n, int ii)
{

	for (int i = 1; i <= ii; i++)
	{
		if (n < 0)
			break;
		if (i <= n)
		{
			if (i == 1)
			{
				for (int j = 0; j < n; j++)
					sumStack[top++] = 1;
				for (int i = 0; i < top; i++)
					printf("%d",sumStack[i]);
				printf("\n");
				top = top - n;
			}
			else {

				sumStack[top++] = i;
				n = n - i;
				if (n >= 0)
					reverse(sumStack, top, n, i);
				else {
					if (top >= 0)
						printf("%d", sumStack[--top]);
				}
			}

		}
		else
		{

			sumStack[top++] = i;
			for (int j = 0; j < n; j++)
				sumStack[top++] = 1;

			for (int i = 0; i < top; i++)
				printf("%d", sumStack[i]);
			printf("\n");
			top--;
		}
	}
}

*/

void Func(int sumstack[], int n, int i, int top)
{
	n = n - i;
	sumstack[top++] = i;
	for (int j = 1; j <= i; j++)
	{
		if (n - j >= 0)
			Func(sumstack, n, j, top);
		if (n == 0) {
			printf("%d = ", temp);
			for (int k = 0; k < top; k++)
			{
				printf(" %d ", sumstack[k]);
				if (k < top - 1)
					printf("+");
			}
			printf("\n");
		}
		if (n - j < 0)
			break;

	}
}

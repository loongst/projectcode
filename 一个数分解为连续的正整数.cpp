#include<stdio.h>
int main()
{
	int num;
	int M_count;
	int temp;
	while (1) {
		printf("需要分解的数字：");
		scanf("%d", &num);
		for (int i = 0; i < 100; i++)
		{
			if (i*(i + 1) / 2 >= num)
			{
				M_count = i;
				break;
			}
		}
		for (int j = M_count; j >= 2; j--)
		{
			temp = j * (j + 1) / 2;
			for (int i = 0; i < num; i++)
			{
				if (num == (temp + j * i))
				{
					printf("%d = ", num);
					for (int k = 1; k <= j; k++)
					{
						printf("%d", k + i);
						if (k < j)
							printf("+");

					}
					printf("\n");

				}
			}

		}
	}
	return 0;
}
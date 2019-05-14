
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>

#include "ExpressionFunc.h"
//#include "pch.h"
////////////////////////

//表达式的项
struct SExpItem
{
	int				m_itemType;
	int				m_operatorType;
	double			m_itemValue;
};

////////////////////////


/*
功能：
	初始化算术表达式
参数：
	pExp：算术表达式
返回：
	0：正确
	其它：错误
*/
int ExpressionInit(struct SExpression *pExp)
{
	if (pExp == NULL)
		return 200;

	memset(pExp, 0x00, sizeof(struct SExpression));
	pExp->m_value = 0.0;
	return 0;
}

/*中缀表达式转后缀表达式
转换过程需要用到栈，具体过程如下：

1）如果遇到操作数，我们就直接将其输出。

2）如果遇到操作符，则我们将其放入到栈中，遇到左括号时我们也将其放入栈中。

3）如果遇到一个右括号，则将栈元素弹出，将弹出的操作符输出直到遇到左括号为止。注意，左括号只弹出并不输出。

4）如果遇到任何其他的操作符，如（“+”， “*”，“（”）等，从栈中弹出元素直到遇到发现更低优先级的元素(或者栈为空)为止。弹出完这些元素后，才将遇到的操作符压入到栈中。有一点需要注意，只有在遇到" ) "的情况下我们才弹出" ( "，其他情况我们都不会弹出" ( "。

5）如果我们读到了输入的末尾，则将栈中所有元素依次弹出。
*/
int ConvertExp(struct SExpression *pExp, struct HZExpression *hzexp, int expStrlen)
{
	int HZtop = 0;  //后缀表达式当前位置
	int pex = 0;    //统计数字长度
	int j = 0;
	for (int i = 0; i < expStrlen; i++)
	{
		
		char temp[256] = {};
		//逐项读取pExp->m_expStr中的数字，暂存到temp中，数值项读取结束则放入后缀表达式数组中
		if (pExp->m_expStr[i] >= '0'&&pExp->m_expStr[i] <= '9' || pExp->m_expStr[i] == '.')
		{
			pex++;
			
			//若某一数字的后一位是"+-*/（）和结尾'\0' "其中的一项，则该数字是数值项的最后一位
			if (pExp->m_expStr[i + 1] == '+' || pExp->m_expStr[i + 1] == '-' || pExp->m_expStr[i + 1] == '*' || pExp->m_expStr[i + 1] == '/' || pExp->m_expStr[i + 1] == '(' || pExp->m_expStr[i + 1] == ')' || pExp->m_expStr[i + 1] == '\0')
			{
				for (int k = i - pex + 1; k <= i; k++)
				{
					temp[j++] = pExp->m_expStr[k];
				}
				pExp->m_operandStack[pExp->m_operandTop++] = atof(temp);
				hzexp[HZtop].exp_operand = atof(temp);
				hzexp[HZtop].exp_operator = '\0';
				hzexp[HZtop++].exp_item_type = ITEM_TYPE_OPERAND;
				j = 0;
				pex = 0;
			}

		}

		else if (pExp->m_expStr[i] == '+' || pExp->m_expStr[i] == '-' || pExp->m_expStr[i] == '*' || pExp->m_expStr[i] == '/' || pExp->m_expStr[i] == '(')
		{
			//表达式中有负数时，在负号前加0，将负数转换为减法表达式
			if ((pExp->m_expStr[i] == '-' &&i<1)||(pExp->m_expStr[i] == '-' &&pExp->m_expStr[i-1] == '('))
			{
				hzexp[HZtop].exp_item_type = ITEM_TYPE_OPERAND;
				hzexp[HZtop].exp_operand = 0;
				hzexp[HZtop++].exp_operator = '\0';
			}
			if (pExp->m_operatorTop == 0)
			{
				pExp->m_operatorStack[pExp->m_operatorTop++] = pExp->m_expStr[i];
			}
			else {
				//判断当前运算符和栈中的优先级，将优先级高的弹出
				for (int a = pExp->m_operatorTop - 1; a >= 0; a--)
				{
					if (getPrioraty(pExp->m_expStr[i]) <= getPrioraty(pExp->m_operatorStack[a]) && pExp->m_operatorStack[a] != '(')
					{
						//pExp->m_operandStack[pExp->m_operandTop++] = pExp->m_operatorStack[--pExp->m_operatorTop];
						hzexp[HZtop].exp_operator = pExp->m_operatorStack[--pExp->m_operatorTop];
						hzexp[HZtop].exp_operand = 0x00;
						hzexp[HZtop++].exp_item_type = ITEM_TYPE_OPERATOR;
					}
					else
						break;
				}
				pExp->m_operatorStack[pExp->m_operatorTop++] = pExp->m_expStr[i]; //当前运算符进栈
			}
		}
		//遇到’）‘时，运算符出栈，直至'('
		else if (pExp->m_expStr[i] == ')'&&pExp->m_operatorTop > 0)
		{
			while (pExp->m_operatorStack[--pExp->m_operatorTop] != '(')
			{
				hzexp[HZtop].exp_operator = pExp->m_operatorStack[pExp->m_operatorTop];
				hzexp[HZtop].exp_operand = 0x00;
				hzexp[HZtop++].exp_item_type = ITEM_TYPE_OPERATOR;
			}
			
		}

		//读到字符串最后一位时，操作符全部出栈
		if (i == expStrlen - 1)
		{
			while (pExp->m_operatorTop > 0)
			{
				hzexp[HZtop].exp_operator = pExp->m_operatorStack[--pExp->m_operatorTop];
				hzexp[HZtop].exp_operand = 0x00;
				hzexp[HZtop++].exp_item_type = ITEM_TYPE_OPERATOR;
			}
		}
	}
	return HZtop; 
}

int getPrioraty(char m_opreator)
{
	switch (m_opreator)
	{
	case '+':
		return 1;
	case '-':
		return 2;
	case '*':
		return 3;
	case '/':
		return 4;
	case '(':
		return 5;
	case ')':
		return 6;
	default:
		return 0;

	}

}

/*三项计算值*/
double getValue(double a, double b, char c)
{
	switch (c)
	{
	case '+':
		return a + b;
	case '-':
		return a - b;
	case '*':
		return a * b;
	case '/':
		return a / b;
	default:
		break;
	}
}

/*
功能：
	计算算术表达式的值
参数：
	pExp：算术表达式
		算术表达式由操作符、操作数组成
		操作符：负-、加+、减-、乘*、除/、左括号(、右括号)
		操作数：0--9和小数点组成的整数和小数
返回：
	0：正确，算术表达式的值在pExp->m_value中
	其它：错误
*/
int ExpressionEvaluate(struct SExpression *pExp, struct HZExpression *hzexp, int HZtop)
{
	int p=HZtop;
	
		//获取一个表达式项

		//得到的是操作数：操作数处理

		//得到的是操作符或结束符：操作符、结束符处理


	if(p==1)				//只有一项操作数时，直接输出
		pExp->m_value = hzexp[0].exp_operand;
	else {
		for (int i = 0; i < p; i++)
		{
			if (hzexp[i].exp_item_type == ITEM_TYPE_OPERATOR) //读到运算符则取出前两位进行计算
			{
				hzexp[i - 2].exp_operand = getValue(hzexp[i - 2].exp_operand, hzexp[i - 1].exp_operand, hzexp[i].exp_operator);
				hzexp[i - 2].exp_operator = '\0';
				hzexp[i - 2].exp_item_type = ITEM_TYPE_OPERAND;
				for (int s = i; s < HZtop - 1; s++)
				{
					hzexp[s - 1].exp_item_type = hzexp[s + 1].exp_item_type;
					hzexp[s - 1].exp_operand = hzexp[s + 1].exp_operand;
					hzexp[s - 1].exp_operator = hzexp[s + 1].exp_operator;

				}
				HZtop = HZtop - 2;        
				
				i = i - 2;         //后缀表达式位置后退两位
				if (HZtop == 1)
				{
					pExp->m_value = hzexp[--HZtop].exp_operand;
					break;
				}

			}
		}
	}

	

	return 100;
}


//////////////////////////



#ifndef __EXPRESSION_FUNC_H__
#define __EXPRESSION_FUNC_H__			1

//表达式长度
#define MAX_EXPRESSION_LENGTH		256

//运算项类型
#define ITEM_TYPE_NONE			0 //无
#define ITEM_TYPE_OPERATOR		1 //操作符
#define ITEM_TYPE_OPERAND		2 //操作数

//操作符类型
#define OPERATOR_TYPE_NONE		0 //无
#define OPERATOR_TYPE_PLUS		1 //加
#define OPERATOR_TYPE_MINUS		2 //减
#define OPERATOR_TYPE_MULTIPLY	3 //乘
#define OPERATOR_TYPE_DIVIDE	4 //除
#define OPERATOR_TYPE_NEGATIVE	5 //负
#define OPERATOR_TYPE_LEFTP		6 //左括号
#define OPERATOR_TYPE_RIGHTP	7 //右括号
#define OPERATOR_TYPE_END		8 //结束

//最小除数
#define SAMLL_NUMBER			0.000000001

/////////////////////////////

//表达式
struct SExpression
{
	//表达式字符串
	char			m_expStr[MAX_EXPRESSION_LENGTH];
	//值
	double			m_value;


	//以下是可能的其它字段

	//表达式长度
//	int				m_HZtop;
	//表达式当前位置
	int				m_curPos;

	//操作符堆栈
	int				m_operatorStack[MAX_EXPRESSION_LENGTH];
	int				m_operatorTop;
	//操作数堆栈
	double			m_operandStack[MAX_EXPRESSION_LENGTH];
	int				m_operandTop;
};


/*后缀表达式项结构体*/
struct HZExpression
{
	char exp_operator; //运算符
	double exp_operand; //数值
	int exp_item_type;  //类型标记 
};


/*
功能：
	初始化算术表达式
参数：
	pExp：算术表达式
返回：
	0：正确
	其它：错误
*/
int ExpressionInit(struct SExpression *pExp);

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
int ExpressionEvaluate(struct SExpression *pExp, struct HZExpression *hzexp,int n);

/*转换中缀表达式为后缀表达式*/
int ConvertExp(struct SExpression *pExp, struct HZExpression *hzexp, int expStrlen);

/*操作符的优先级*/
int getPrioraty(char m_opreator);

/*计算值*/
double getValue(double a, double b, char c);
#endif


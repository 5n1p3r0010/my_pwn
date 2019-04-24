#include"stdlib.h"

int main()
{
	char s1[]="1;sh;";
	char s2[]="2||sh";
	char s3[]="$0";
	system(s1);
	system(s2);
	system(s3);
}
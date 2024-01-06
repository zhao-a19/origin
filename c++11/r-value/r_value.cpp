#include <iostream>

int main() {
    //左值: num可以取地址，所以是左值
    int num = 9;
    //左值引用：只能对左值取引用
	int & a = num;
    
    //右值
    //右值引用
    int && b = 9;
    
    //常量右值引用
    const int && c = 9;
    
    //常量左值引用: d只能是num的别名
    const int & d = num; 
    const int & e = b;
    const int & f = c;
    const int & g = a;

    return 0;
}

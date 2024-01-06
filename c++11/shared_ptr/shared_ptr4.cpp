#include <iostream>
#include <memory>
using namespace std;

void func(int *p) {
     delete p;
     cout << "int 内存被释放了";
}

int main() {
   
   shared_ptr<int> ptr1(new int(512), func);
   
   return 0;
}

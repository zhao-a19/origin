#include <iostream>
#include <memory>
using namespace std;

unique_ptr<int> func() {
   return unique_ptr<int> (new int(512));
}

int main() {
   unique_ptr<int> ptr1(new int(10));
   unique_ptr<int> ptr2 = move(ptr1);
   unique_ptr<int> ptr3 = func();
   return 0;
}

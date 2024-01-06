#include <iostream>
#include <memory>
using namespace std;

int main() {
   unique_ptr<int> ptr1(new int(10));
   unique_ptr<int> ptr2 = move(ptr1);
   ptr1.reset();
   ptr2.reset(new int(512));
   return 0;
}

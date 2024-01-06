#include <iostream>
#include <memory>
using namespace std;

int main() {
   unique_ptr<int> ptr1(new int(10));
   unique_ptr<int> ptr2 = move(ptr1);
   ptr2.reset(new int(512));
   cout << *ptr2.get() <<endl;
   return 0;
}

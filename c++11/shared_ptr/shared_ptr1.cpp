#include <iostream>
#include <memory>
using namespace std;

int main() {
   
   shared_ptr<int> ptr1(new int(512));
   cout << "count1: "<< ptr1.use_count() << endl;
   
   shared_ptr<int> ptr2(ptr1);
   cout << "count2: " << ptr2.use_count() << endl;
   
   shared_ptr<int> ptr3 = ptr1;
   cout << "count3: " << ptr3.use_count() << endl;

   shared_ptr<int> ptr4(std::move(ptr1));
   cout << "count4: "<< ptr4.use_count() << endl;

   return 0;
}

/* This software was developed at the National Institute of Standards and
 * Technology by employees of the Federal Government in the course of their
 * official duties. Pursuant to title 17 Section 105 of the United States
 * Code this software is not subject to copyright protection and is in the
 * public domain. NIST assumes no responsibility whatsoever for its use by
 * other parties, and makes no guarantees, expressed or implied, about its
 * quality, reliability, or any other characteristic.

 * We would appreciate acknowledgement if the software is used.
 * The SAMATE project website is: http://samate.nist.gov
*/
 

#include <iostream>

const int N = 2; // array size

class PrivatePublic {
public:
        PrivatePublic() {
                data[0] = 8;
                data[1] = 7;
        }

        int *getData() { return data; }	/* BAD */

        void printData() {
                for (int i = 0; i < N; i++) {
                        std::cout << data[i] << " ";
                }
                std::cout << std::endl;
        }

private:
        int data[N];
};

int main () {
        PrivatePublic test;

        test.printData();

        // get private array of PrivatePublic
        // this allows us to modify the array elements
        int *ptr = test.getData();

        ptr[0] = 1;
        ptr[1] = 2;

        test.printData();

        return 0;
}


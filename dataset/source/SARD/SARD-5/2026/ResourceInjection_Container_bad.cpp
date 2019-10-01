
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


#include <fstream>
#include <iostream>
#include <string>
using namespace std;

typedef class cont_o cont;

class cont_o
   {
       private:
         string name; 
       public:
         cont_o(const string& n)
           : name(n) 
         { 
         }
         string getName(){
         	return name;
         }
         ~cont_o(){
	        
         }
};

int main(int argc, const char *argv[])
{
	if (argc > 1){
	    cont container(argv[1]);
		ifstream in(container.getName().c_str());
		char temp[100];
		while(!in.getline(temp, 100).fail()&&!in.eof())
		{
			cout << temp<<endl;
		}
		cout << temp<<endl;
	}
    return 0;
}

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

const string ALLOWED[5]={
  "users_site.dat",
   "users_reg.dat",
   "users_info.dat",
   "admin.dat",
   "services.dat.cxx"
};

bool allowed(string in){
	for(int i=0;i<5;i++){
		if(ALLOWED[i]==in){
			return true;
		}
	}
	return false;
}

int main(int argc, const char *argv[])
{
	if(argc>1){
		string fName(argv[1]);
		if(allowed(fName)){
			ifstream in(fName.c_str());
			char temp[100];
			while(!in.getline(temp, 100).fail()&&!in.eof())
			{
				cout <<temp<<endl;
			}
			cout << temp<<endl;
		}
	}
    return 0;
}

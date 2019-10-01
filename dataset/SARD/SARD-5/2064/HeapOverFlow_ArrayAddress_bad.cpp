
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
using namespace std;
typedef char * cptr;

int main(int argc, const char *argv[])
{
	cptr buf[3] = {"a","b","c"};
	buf[2] = new (nothrow) char[5*sizeof(char)];
	if (buf[2] == 0)
    		cout << "Error: memory could not be allocated";
	else 
		{if (argc > 1)
		buf[2][strlen(argv[1])-1]='a';
		delete [] buf[2];}
	return 0;
}

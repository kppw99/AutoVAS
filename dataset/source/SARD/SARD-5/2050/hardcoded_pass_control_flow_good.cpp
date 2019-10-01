
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
#include <string>
using namespace std;

string getUserPassword(const string& username) {
	string pass;
	// get the system password or do a query etc.
	return pass;
}


bool user_ok(const string& userpass, const string& username)
{
	if (userpass == getUserPassword(username))
		return true;
	return false;
}

int main(int argc, char *argv[])
{
	if (argc > 2)
	{
		if (user_ok(argv[2], argv[1]))
			cout << "You are now identified." << endl;
		else
			cout << "Your password is not valid, please reenter it." << endl;
	}
	else
		cout << "Usage: ./bin <user> <password>" << endl;

	return 0;
}

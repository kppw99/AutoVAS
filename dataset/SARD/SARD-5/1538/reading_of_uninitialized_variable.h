#include "test.h"
#include <stdlib.h>

// Reading of an uninitialized variable.
class reading_of_uninitialized_variable : public test
{
public:
	reading_of_uninitialized_variable(void);
	~reading_of_uninitialized_variable(void);
	void runTests(bool mayCrash);

	int v1(void);
	void v2(void);
};

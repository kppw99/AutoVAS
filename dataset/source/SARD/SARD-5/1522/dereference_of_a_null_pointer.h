#include "test.h"
#include <stdlib.h>

// A null pointer is dereferenced.
class dereference_of_a_null_pointer : public test
{
public:
	dereference_of_a_null_pointer(void);
	~dereference_of_a_null_pointer(void);
	void runTests(bool mayCrash);

	void v1(int* p);
};

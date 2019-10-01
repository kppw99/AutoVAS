#include "dereference_of_a_null_pointer.h"

// Constructor.
dereference_of_a_null_pointer::dereference_of_a_null_pointer(void)
{
}

// Destructor.
dereference_of_a_null_pointer::~dereference_of_a_null_pointer(void)
{
}

// Runs all tests.
void dereference_of_a_null_pointer::runTests(bool mayCrash)
{
	if (mayCrash != 0)
	{
		v1(NULL);
	}
}

// Simple case that is NULL.
void dereference_of_a_null_pointer::v1(int* p)
{
    int x;

    if (p == NULL)
    {
        x = 0;
    }
    else
    {
        x = *p;
    }
    *p = x;   // ERROR: p is NULL.
}

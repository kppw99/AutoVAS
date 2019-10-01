#include "reading_of_uninitialized_variable.h"

// Constructor.
reading_of_uninitialized_variable::reading_of_uninitialized_variable(void)
{
}

// Destructor.
reading_of_uninitialized_variable::~reading_of_uninitialized_variable(void)
{
}

// Runs all tests.
void reading_of_uninitialized_variable::runTests(bool mayCrash)
{
	v1();
	v2();
}

// v1: simple case.
int reading_of_uninitialized_variable::v1(void)
{
	int x[10];

	x[0] = 0;
	return x[3];   // ERROR: "x" is not initialized
}

// v2: more complex example with nested uninitialized variable.
void reading_of_uninitialized_variable::v2(void)
{
	struct S2 *p;
	int i;

    p = (struct S2*)malloc(sizeof(struct S2));
	p->a = 0;
	p->b = 0;
	
	i = p->c; // ERROR: p->c is uninitialized.
	free(p);
}

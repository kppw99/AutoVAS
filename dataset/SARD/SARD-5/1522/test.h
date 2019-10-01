#pragma once

// Types used by many tests.
struct S
{
    int a;
    int b;
    char c[100];
};

struct S2
{
    int a;
    int b;
    int c;
};

struct S3
{
	int *a;
	int *b;
	int *c;
};

// Base class for all tests.
class test
{
public:
	test(void);
	virtual ~test(void);
	// Some tests may crash the program. To desactivate these tests,
	// mayCrash = 0, otherwise all tests will be executed.
	virtual void runTests(bool mayCrash) = 0;
};

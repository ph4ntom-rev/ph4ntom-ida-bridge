/* Compile only this fixture for the optional IDA smoke test. */
int fixture_add(int a, int b) { return a + b; }
int fixture_branch(int a) { return a > 7 ? fixture_add(a, 2) : a - 1; }
int main(void) { return fixture_branch(8) == 10 ? 0 : 1; }
volatile int fixture_patch_target = 7;

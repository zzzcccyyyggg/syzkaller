typedef unsigned long size_t;

#define NOINLINE __attribute__((noinline))
#define USED __attribute__((used))

int shared_a;
int shared_b;
unsigned long shared_flags;
char global_src[64];
char global_dst[64];
_Atomic int atomic_counter;
volatile int sink;

struct bitfield_holder {
	unsigned int a : 1;
	unsigned int b : 1;
	unsigned int c : 6;
};

struct bitfield_holder shared_bits;

NOINLINE USED int plain_global_read(void)
{
	return shared_a;
}

NOINLINE USED void plain_global_write(int v)
{
	shared_a = v;
}

NOINLINE USED int atomic_load_case(void)
{
	return __c11_atomic_load(&atomic_counter, __ATOMIC_SEQ_CST);
}

NOINLINE USED void atomic_store_case(int v)
{
	__c11_atomic_store(&atomic_counter, v, __ATOMIC_SEQ_CST);
}

NOINLINE USED int atomic_rmw_case(void)
{
	return __c11_atomic_fetch_add(&atomic_counter, 1, __ATOMIC_SEQ_CST);
}

NOINLINE USED void atomic_nonatomic_side(int v)
{
	*(int *)&atomic_counter = v;
}

NOINLINE USED void flags_bit0(void)
{
	shared_flags |= 1UL << 0;
}

NOINLINE USED void flags_bit1(void)
{
	shared_flags |= 1UL << 1;
}

NOINLINE USED void bitfield_a(void)
{
	shared_bits.a = 1;
}

NOINLINE USED void bitfield_b(void)
{
	shared_bits.b = 1;
}

NOINLINE USED void memcpy_globals(size_t n)
{
	__builtin_memcpy(global_dst, global_src, n);
}

NOINLINE USED int *helper_return_shared(void)
{
	return &shared_b;
}

NOINLINE USED int helper_return_load(void)
{
	return *helper_return_shared();
}

NOINLINE USED int phi_select_case(int cond)
{
	int *p = cond ? &shared_a : &shared_b;
	return *p;
}

NOINLINE USED int stack_spill_only(int v)
{
	int local = v + 1;
	int tmp = local * 3;
	return tmp - local;
}

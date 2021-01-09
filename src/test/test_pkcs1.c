#include "../common.h"

uint8_t propagate_ones(uint8_t x);
size_t propagate_ones_long(uint8_t x);
void safe_select(const uint8_t *in1, const uint8_t *in2, uint8_t *out, uint8_t choice, size_t len);
size_t safe_select_idx(size_t in1, size_t in2, uint8_t choice);
uint8_t safe_cmp(const uint8_t *in1, const uint8_t *in2,
                 const uint8_t *eq_mask, const uint8_t *neq_mask,
                 size_t len);
size_t safe_search(const uint8_t *in1, uint8_t c, size_t len);

const uint8_t one[] = "1";
const uint8_t zero[] = "0";
const uint8_t onezero[] = "10";
const uint8_t oneone[] = "11";
const uint8_t zeroone[] = "01";
const uint8_t zerozero[] = "00";

void test_propagate_ones()
{
    assert(propagate_ones(0) == 0);
    assert(propagate_ones(1) != 0);
    assert(propagate_ones(0x40) != 0);
    assert(propagate_ones(0x80) != 0);
}

void test_propagate_ones_long()
{
    assert(propagate_ones_long(0) == 0);
    assert(propagate_ones_long(1) == (size_t)-1);
    assert(propagate_ones_long(0x40) == (size_t)-1);
    assert(propagate_ones_long(0x80) == (size_t)-1);
}

void test_safe_select()
{
    uint8_t out[10];

    safe_select(one, zero, out, 0, 1);
    assert(memcmp(one, out, 1) == 0);

    safe_select(one, zero, out, 1, 1);
    assert(memcmp(zero, out, 1) == 0);

    safe_select(onezero, zerozero, out, 0, 2);
    assert(memcmp(onezero, out, 1) == 0);

    safe_select(onezero, zerozero, out, 01, 2);
    assert(memcmp(zerozero, out, 1) == 0);
}

void test_safe_select_idx()
{
    assert(safe_select_idx(0, 1, 0) == 0);
    assert(safe_select_idx(0, 1, 1) == 1);
    assert(safe_select_idx(0x100004, 0x223344, 0) == 0x100004);
    assert(safe_select_idx(0x100004, 0x223344, 1) == 0x223344);
}

void test_safe_cmp()
{
    uint8_t res;

    res = safe_cmp(onezero, onezero,
                   (uint8_t*)"\xFF\xFF",
                   (uint8_t*)"\x00\x00",
                   2);
    assert(res == 0);

    res = safe_cmp(onezero, zerozero,
                   (uint8_t*)"\xFF\xFF",
                   (uint8_t*)"\x00\x00",
                   2);
    assert(res != 0);

    res = safe_cmp(onezero, oneone,
                   (uint8_t*)"\xFF\xFF",
                   (uint8_t*)"\x00\x00",
                   2);
    assert(res != 0);

    res = safe_cmp(onezero, oneone,
                   (uint8_t*)"\xFF\x00",
                   (uint8_t*)"\x00\x00",
                   2);
    assert(res == 0);

    /** -- **/

    res = safe_cmp(onezero, onezero,
                   (uint8_t*)"\x00\x00",
                   (uint8_t*)"\xFF\xFF",
                   2);
    assert(res != 0);

    res = safe_cmp(oneone, zerozero,
                   (uint8_t*)"\x00\x00",
                   (uint8_t*)"\xFF\xFF",
                   2);
    assert(res == 0);

    res = safe_cmp(onezero, oneone,
                   (uint8_t*)"\x00\x00",
                   (uint8_t*)"\x00\xFF",
                   2);
    assert(res == 0);

    /** -- **/

    res = safe_cmp(onezero, oneone,
                   (uint8_t*)"\xFF\x00",
                   (uint8_t*)"\x00\xFF",
                   2);
    assert(res == 0);
}

void test_safe_search()
{
    size_t res;

    res = safe_search((uint8_t*)"ABCDEFB", 0x41, 6);
    assert(res == 0);

    res = safe_search((uint8_t*)"ABCDEFB", 0x42, 6);
    assert(res == 1);

    res = safe_search((uint8_t*)"ABCDEFB", 0x47, 6);
    assert(res == 6);
}

int main(void)
{
    test_propagate_ones();
    test_propagate_ones_long();
    test_safe_select();
    test_safe_select_idx();
    test_safe_cmp();
    test_safe_search();
    return 0;
}

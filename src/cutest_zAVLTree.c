
#include "config_xor.h"

#include <string.h>
#include "CuTest.h"
#include "zAVLTree.h"

struct ztest {
  char name[32];
};

static zAVLTree * ztest_tree   = NULL;

static zAVLKey ztest_key (void const * arg)
{
  const struct ztest * sa = (const struct ztest *) arg;
  return (zAVLKey) sa->name;
}

static void free_node (void * inptr)
{
  struct ztest * ptr = (struct ztest *) inptr;
  ptr->name[0] = '\0';
}

void Test_zAVLTree(CuTest *tc) {
  zAVLCursor    cursor;

  int result;
  int counter = 0;

  struct ztest z1 = { "abc" };
  struct ztest z2 = { "aac" };
  struct ztest z3 = { "aaa1" };
  struct ztest z4 = { "aaa3" };
  struct ztest z5 = { "aaa2" };
  struct ztest z6 = { "aaa6" };
  struct ztest z7 = { "aaa5" };
  struct ztest z8 = { "aaa4" };

  struct ztest * ptr;

  ptr = zAVLFirst(&cursor, ztest_tree);
  CuAssertTrue(tc, NULL == ptr);

  ztest_tree = zAVLAllocTree (ztest_key);
  CuAssertPtrNotNull(tc, ztest_tree);

  do {

  ++counter;

  result = zAVLInsert(ztest_tree, &z1);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z2);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z3);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z4);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z5);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z6);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z7);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z8);
  CuAssertTrue(tc, 0 == result);

  ptr = zAVLFirst(&cursor, ztest_tree);
  CuAssertStrEquals(tc, ptr->name, z3.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z5.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z4.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z8.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z7.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z6.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z2.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z1.name);
  ptr = zAVLNext(&cursor);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLInsert(ztest_tree, &z8);
  CuAssertTrue(tc, 0 != result);
  result = zAVLInsert(ztest_tree, &z7);
  CuAssertTrue(tc, 0 != result);
  result = zAVLInsert(ztest_tree, &z6);
  CuAssertTrue(tc, 0 != result);
  result = zAVLInsert(ztest_tree, &z5);
  CuAssertTrue(tc, 0 != result);

  ptr = zAVLSearch(ztest_tree, z1.name);
  CuAssertStrEquals(tc, ptr->name, z1.name);
  ptr = zAVLSearch(ztest_tree, z2.name);
  CuAssertStrEquals(tc, ptr->name, z2.name);
  ptr = zAVLSearch(ztest_tree, z3.name);
  CuAssertStrEquals(tc, ptr->name, z3.name);
  ptr = zAVLSearch(ztest_tree, z4.name);
  CuAssertStrEquals(tc, ptr->name, z4.name);

  ptr = zAVLFirst(&cursor, ztest_tree);
  CuAssertStrEquals(tc, ptr->name, z3.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z5.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z4.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z8.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z7.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z6.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z2.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z1.name);
  ptr = zAVLNext(&cursor);
  CuAssertTrue(tc, NULL == ptr);


  ptr = zAVLSearch(ztest_tree, z5.name);
  CuAssertStrEquals(tc, ptr->name, z5.name);
  ptr = zAVLSearch(ztest_tree, z6.name);
  CuAssertStrEquals(tc, ptr->name, z6.name);
  ptr = zAVLSearch(ztest_tree, z7.name);
  CuAssertStrEquals(tc, ptr->name, z7.name);
  ptr = zAVLSearch(ztest_tree, z8.name);
  CuAssertStrEquals(tc, ptr->name, z8.name);
  ptr = zAVLSearch(ztest_tree, "foobar");
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z8.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z8.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z3.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z3.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z1.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z1.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLInsert(ztest_tree, &z1);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z8);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z3);
  CuAssertTrue(tc, 0 == result);

  ptr = zAVLFirst(&cursor, ztest_tree);
  CuAssertStrEquals(tc, ptr->name, z3.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z5.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z4.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z8.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z7.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z6.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z2.name);
  ptr = zAVLNext(&cursor);
  CuAssertStrEquals(tc, ptr->name, z1.name);
  ptr = zAVLNext(&cursor);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z1.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z1.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z2.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z2.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z3.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z3.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z4.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z4.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z5.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z5.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z6.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z6.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z7.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z7.name);
  CuAssertTrue(tc, NULL == ptr);

  result = zAVLDelete(ztest_tree, z8.name);
  CuAssertTrue(tc, 0 == result);
  ptr = zAVLSearch(ztest_tree, z8.name);
  CuAssertTrue(tc, NULL == ptr);

} while (counter < 100);

  result = zAVLInsert(ztest_tree, &z1);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z2);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z3);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z4);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z5);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z6);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z7);
  CuAssertTrue(tc, 0 == result);
  result = zAVLInsert(ztest_tree, &z8);
  CuAssertTrue(tc, 0 == result);

  zAVLFreeTree (ztest_tree, free_node);
  CuAssertTrue (tc, z1.name[0] == '\0');
  CuAssertTrue (tc, z2.name[0] == '\0');
  CuAssertTrue (tc, z3.name[0] == '\0');
  CuAssertTrue (tc, z4.name[0] == '\0');
  CuAssertTrue (tc, z5.name[0] == '\0');
  CuAssertTrue (tc, z6.name[0] == '\0');
  CuAssertTrue (tc, z7.name[0] == '\0');
  CuAssertTrue (tc, z8.name[0] == '\0');
}

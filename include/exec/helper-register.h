#ifndef HELPER_REGISTER_H
#define HELPER_REGISTER_H

#include "qemu/compiler.h"
#include "exec/helper-head.h"

/* Need one more level of indirection before stringification
   to get all the macros expanded first.  */
#define str(s) tostring(s)

#define DEF_HELPER_FLAGS_0(NAME, FLAGS, ret) \
    tcg_register_helper(HELPER(NAME), str(NAME), FLAGS, dh_sizemask(ret, 0));

#define DEF_HELPER_FLAGS_1(NAME, FLAGS, ret, t1) \
    tcg_register_helper(HELPER(NAME), str(NAME), FLAGS, \
        dh_sizemask(ret, 0) | dh_sizemask(t1, 1));

#define DEF_HELPER_FLAGS_2(NAME, FLAGS, ret, t1, t2) \
    tcg_register_helper(HELPER(NAME), str(NAME), FLAGS, \
        dh_sizemask(ret, 0) | dh_sizemask(t1, 1) | dh_sizemask(t2, 2));

#define DEF_HELPER_FLAGS_3(NAME, FLAGS, ret, t1, t2, t3) \
    tcg_register_helper(HELPER(NAME), str(NAME), FLAGS, \
        dh_sizemask(ret, 0) | dh_sizemask(t1, 1) | dh_sizemask(t2, 2) \
        | dh_sizemask(t3, 3));

#define DEF_HELPER_FLAGS_4(NAME, FLAGS, ret, t1, t2, t3, t4) \
    tcg_register_helper(HELPER(NAME), str(NAME), FLAGS, \
        dh_sizemask(ret, 0) | dh_sizemask(t1, 1) | dh_sizemask(t2, 2) \
        | dh_sizemask(t3, 3) | dh_sizemask(t4, 4));

#define DEF_HELPER_FLAGS_5(NAME, FLAGS, ret, t1, t2, t3, t4, t5) \
    tcg_register_helper(HELPER(NAME), str(NAME), FLAGS, \
        dh_sizemask(ret, 0) | dh_sizemask(t1, 1) | dh_sizemask(t2, 2) \
        | dh_sizemask(t3, 3) | dh_sizemask(t4, 4) | dh_sizemask(t5, 5));

#define DEF_HELPER_FLAGS_6(NAME, FLAGS, ret, t1, t2, t3, t4, t5, t6) \
    tcg_register_helper(HELPER(NAME), str(NAME), FLAGS, \
        dh_sizemask(ret, 0) | dh_sizemask(t1, 1) | dh_sizemask(t2, 2) \
        | dh_sizemask(t3, 3) | dh_sizemask(t4, 4) | dh_sizemask(t5, 5) \
        | dh_sizemask(t6, 6));

#include "helper.h"

#undef str
#undef DEF_HELPER_FLAGS_0
#undef DEF_HELPER_FLAGS_1
#undef DEF_HELPER_FLAGS_2
#undef DEF_HELPER_FLAGS_3
#undef DEF_HELPER_FLAGS_4
#undef DEF_HELPER_FLAGS_5
#undef DEF_HELPER_FLAGS_6

#endif /* HELPER_REGISTER_H */

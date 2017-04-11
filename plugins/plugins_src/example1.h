#ifndef EXAMPLE1_H
#define EXAMPLE1_H

typedef void (* temp_func_wout_params)(void);
typedef void (* temp_func_w_params)(int p1, int p2);

struct SSS { temp_func_wout_params f1; temp_func_w_params f2; };

#endif
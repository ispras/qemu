#ifndef FILE_MONITOR_H
#define FILE_MONITOR_H

#include "handle_map.h"

typedef HandleMap * (* get_open_files_list)(void);

struct fileMonFuncs { get_open_files_list f1; };

#endif
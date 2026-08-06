#ifndef CSQLITE_SHIM_H
#define CSQLITE_SHIM_H

#if __has_include(<sqlite3.h>)
#include <sqlite3.h>
#elif __has_include("/usr/include/sqlite3.h")
#include "/usr/include/sqlite3.h"
#else
#error "SQLite3 header not found"
#endif

#endif /* CSQLITE_SHIM_H */

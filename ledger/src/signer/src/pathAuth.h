/*******************************************************************************
 *   HSM 2.0
 *   (c) 2020 RSK
 *   Path authorization definitions
 ********************************************************************************/

#ifndef PATHAUTH_H
#define PATHAUTH_H

#include <stdbool.h>

#define TOTAL_AUTHORIZED_PATHS 9
#define SINGLE_PATH_SIZE_BYTES 21

// Paths
//
extern const char authPaths[][21];
extern const char noAuthPaths[][21];
extern const int ordered_paths[TOTAL_AUTHORIZED_PATHS];

bool pathRequireAuth(char *path);
bool pathDontRequireAuth(char *path);

const char* get_ordered_path(unsigned int index);

#define KEY_PATH_COUNT() (sizeof(ordered_paths)/sizeof(ordered_paths[0]))
#define PATH_LEN 5

#endif // PATHAUTH_H

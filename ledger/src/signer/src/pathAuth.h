/*******************************************************************************
 *   HSM 2.0
 *   (c) 2020 RSK
 *   Path authorization definitions
 ********************************************************************************/

#ifndef PATHAUTH_H
#define PATHAUTH_H

// Paths
//
extern const char authPaths[][21];
extern const char noAuthPaths[][21];

bool pathRequireAuth(char *path);
bool pathDontRequireAuth(char *path);

#endif // PATHAUTH_H

#ifndef __RUNTIME
#define __RUNTIME

#ifdef HSM_SIMULATOR
#define NON_VOLATILE static
#else
#define NON_VOLATILE static const
#endif

#endif
#pragma once

// must include windows types before using WINAPI
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

	// Unique export names to avoid colliding with any existing symbols in the project:
	__declspec(dllexport) void WINAPI RematchSpeedshot_Init(void);
	__declspec(dllexport) void WINAPI RematchSpeedshot_Shutdown(void);

#ifdef __cplusplus
}
#endif

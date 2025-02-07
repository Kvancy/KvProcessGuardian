#pragma once 
#include <iostream>
#include <WinSvc.h>

BOOL UnloadDriver(const wchar_t* driverName);

void CleanUpRegistry(const wchar_t* driverName);

BOOL LoadDriver(const wchar_t* driverName, const wchar_t* driverPath);


#pragma once
#define WIN32_LEAN_AND_MEAN
#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <polyhook2/CapstoneDisassembler.hpp>
#include <polyhook2/Detour/x86Detour.hpp>
#include <polyhook2/Detour/x64Detour.hpp>

#include "Server.h"

extern std::unique_ptr<Server> server;

void SetupHook();
void RemoveHook();
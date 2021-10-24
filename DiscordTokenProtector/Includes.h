#pragma once
#define WIN32_LEAN_AND_MEAN
#include <iostream>
#include <fstream>
#include <string>
#include <streambuf>
#include <chrono>
#include <map>
#include <functional>

#include <filesystem>

#include <Windows.h>
#include <aclapi.h>

//Useful stuff
#include "Utils/Logger.h"
#include "Utils/Timer.h"

#define FATALERROR(msg)\
	{\
		MessageBoxA(NULL, msg, "DiscordTokenProtector - Fatal Error", MB_ICONSTOP | MB_OK); \
		ExitProcess(1); \
	}
__forceinline void FATALERROR_STR(std::string str) {
	FATALERROR(str.c_str());
}

#define VER "dev-7"

#pragma comment(lib, "OpenGL32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Comctl32.lib")

//The autostart gets flagged by some AV haha
//#define DISABLE_AUTOSTART

//#define YUBIKEYSUPPORT
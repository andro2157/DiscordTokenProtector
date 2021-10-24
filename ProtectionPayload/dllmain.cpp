#include <iostream>
#include <fstream>
#include "Hook.h"
#include "Utils.h"
#include "Server.h"

std::streambuf* CinBuffer, * CoutBuffer, * CerrBuffer;
std::fstream ConsoleInput, ConsoleOutput, ConsoleError;

HMODULE mainModule = nullptr;
DWORD connectionPort = 0;

std::unique_ptr<Server> server;

void RedirectIO()
{
	CinBuffer = std::cin.rdbuf();
	CoutBuffer = std::cout.rdbuf();
	CerrBuffer = std::cerr.rdbuf();
	ConsoleInput.open("CONIN$", std::ios::in);
	ConsoleOutput.open("CONOUT$", std::ios::out);
	ConsoleError.open("CONOUT$", std::ios::out);
	std::cin.rdbuf(ConsoleInput.rdbuf());
	std::cout.rdbuf(ConsoleOutput.rdbuf());
	std::cerr.rdbuf(ConsoleError.rdbuf());
}

void ResetIO()
{
	ConsoleInput.close();
	ConsoleOutput.close();
	ConsoleError.close();
	std::cin.rdbuf(CinBuffer);
	std::cout.rdbuf(CoutBuffer);
	std::cerr.rdbuf(CerrBuffer);
	CinBuffer = NULL;
	CoutBuffer = NULL;
	CerrBuffer = NULL;
}

void MainThread() {
	srand(GetTickCount());

#ifndef _PROD
	AllocConsole();
	RedirectIO();
	SetConsoleCtrlHandler(NULL, true);
#endif

	SetupHook();

	while (connectionPort == 0)
		Sleep(100);

	server = std::make_unique<Server>();

	try {
		server->Connect(static_cast<USHORT>(connectionPort));
	}
	catch (const std::exception& e) {
		std::cout << e.what() << std::endl;
	}

	server->Send("LOADED");

	typedef LONG(NTAPI* NtResumeProcess)(HANDLE ProcessHandle);
	NtResumeProcess pfnNtResumeProcess = reinterpret_cast<NtResumeProcess>(GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtResumeProcess"));
	pfnNtResumeProcess(GetCurrentProcess());

	while (/*!(GetAsyncKeyState(VK_DELETE) & 0x0001)*/1) {
		Sleep(10000);
		server->Send("KeepAlive");
	}

	//It should never reach this
	std::cout << "Unloading..." << std::endl;

	RemoveHook();

#ifndef _PROD
	ResetIO();
	FreeConsole();
#endif

	PostQuitMessage(0);
	FreeLibraryAndExitThread(mainModule, 0);
}

extern "C" __declspec(dllexport) void __stdcall setPort(size_t port) {
	std::cout << "setPort : " << port << std::endl;
	if (connectionPort == 0) {
		connectionPort = port;
		std::cout << "setPort : " << port << std::endl;
	}
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     ) {
	mainModule = hModule;
    DisableThreadLibraryCalls(hModule);

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(MainThread), NULL, NULL, NULL);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


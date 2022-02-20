#pragma once
#include "../Includes.h"
#include <polyhook2/CapstoneDisassembler.hpp>
#include <polyhook2/Detour/x86Detour.hpp>

class ProcessProtection {
public:
	ProcessProtection();
	~ProcessProtection();

	bool ProtectProcess(HANDLE hProcess = nullptr, bool protectThreads = true);
	bool HookCreateThread();
	bool setHandleSecurityInfo(HANDLE handle);

	//TODO add IAT hooks
	/*
	http://www.rohitab.com/discuss/topic/41701-how-to-stop-openprocess-without-inject-all-processes/
	ZwTerminateProcess
    ZwOpenProcess
    ZwSuspendProcess
    ZwSuspendThread
    NtAllocateVirtualMemory
    NtCreateThread
    CreateRemoteThread
    WriteProcessMemory

	*/

	uint64_t getOriginalCreateThread() const { return m_originalCreateThread; };

private:
	HANDLE m_hProcess;
	DWORD m_pid;
	HANDLE m_appMutex;

	std::unique_ptr<PLH::x86Detour> m_detourCreateThread;
	uint64_t m_originalCreateThread;
};

inline std::unique_ptr<ProcessProtection> g_processprotection;
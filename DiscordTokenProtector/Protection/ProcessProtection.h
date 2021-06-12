#pragma once
#include "../Includes.h"

class ProcessProtection {
public:
	ProcessProtection();
	~ProcessProtection();

	bool ProtectProcess(HANDLE hProcess = nullptr);

	//TODO add thread protection, IAT hooks
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

private:
	HANDLE m_hProcess;
	HANDLE m_appMutex;
};

inline std::unique_ptr<ProcessProtection> g_processprotection;
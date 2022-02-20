#include "ProcessProtection.h"
#include <tlhelp32.h>
#include <winternl.h>

ProcessProtection::ProcessProtection() {
	m_hProcess = GetCurrentProcess();
	m_pid = GetCurrentProcessId();
	m_appMutex = CreateMutex(0, 0, TEXT("DiscordTokenProtector"));
	if (m_appMutex == NULL || GetLastError() == ERROR_ALREADY_EXISTS) {
		MessageBox(NULL, TEXT("It seems like an instance of DiscordTokenProtector is already running!"), TEXT("DiscordTokenProtector"), MB_ICONSTOP | MB_OK);
		ExitProcess(1);
	}
}

ProcessProtection::~ProcessProtection() {
	if (!CloseHandle(m_hProcess)) {
		g_logger.warning(sf() << "Failed to close my handle! Error code : " << GetLastError());
	}
	ReleaseMutex(m_appMutex);
}

//StackOverflow + Microsoft Docs
bool ProcessProtection::ProtectProcess(HANDLE hProcess, bool protectThreads) {
	HANDLE handle = m_hProcess;
	if (hProcess) {
		handle = hProcess;
	}

	if (!setHandleSecurityInfo(handle)) return false;

	if (protectThreads) {
		DWORD pid = hProcess ? GetProcessId(hProcess) : m_pid;

		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
		if (hSnap == INVALID_HANDLE_VALUE) {
			g_logger.error(sf() << "Failed ProtectProcess: CreateToolhelp32Snapshot ! Error code : " << GetLastError());
			return false;
		}

		THREADENTRY32 te;
		te.dwSize = sizeof(te);

		if (!Thread32First(hSnap, &te)) {
			g_logger.error(sf() << "Failed ProtectProcess: Thread32First ! Error code : " << GetLastError());
			CloseHandle(hSnap);
			return false;
		}

		do {
			if (te.th32OwnerProcessID != pid)
				continue;

			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
			if (hThread == NULL) {
				g_logger.error(sf() << "Failed ProtectProcess: OpenThread ! Error code : " << GetLastError());
				continue;
			}

			//g_logger.info(sf() << te.th32ThreadID << " " << hThread);

			setHandleSecurityInfo(hThread);

			CloseHandle(hThread);

		} while (Thread32Next(hSnap, &te));

		CloseHandle(hSnap);
	}

	return true;
}

bool ProcessProtection::setHandleSecurityInfo(HANDLE handle) {
	auto pEmptyDacl = std::unique_ptr<ACL>(new ACL);

	ZeroMemory(pEmptyDacl.get(), sizeof(ACL));
	if (!InitializeAcl(pEmptyDacl.get(), sizeof(ACL), ACL_REVISION)) {
		g_logger.error(sf() << "Failed setHandleSecurityInfo: InitializeAcl ! Error code : " << GetLastError());
		return false;
	}

	if (DWORD errCode = SetSecurityInfo(handle, SE_KERNEL_OBJECT,
		DACL_SECURITY_INFORMATION, NULL, NULL, pEmptyDacl.get(), NULL); errCode != ERROR_SUCCESS) {
		g_logger.error(sf() << "Failed setHandleSecurityInfo: SetSecurityInfo ! Error code : " << GetLastError());
		return false;
	}
	return true;
}

HANDLE WINAPI CreateThread_hook(
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	SIZE_T dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	DWORD dwCreationFlags,
	LPDWORD lpThreadId
) {
	HANDLE ret = PLH::FnCast(g_processprotection->getOriginalCreateThread(), &CreateThread_hook)
		(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

	//g_logger.info(sf() << "New thread : " << ret);

	g_processprotection->setHandleSecurityInfo(ret);

	return ret;
}

bool ProcessProtection::HookCreateThread() {
	PLH::CapstoneDisassembler dis(PLH::Mode::x86);
	
	m_detourCreateThread = std::make_unique<PLH::x86Detour>(
		(char*)CreateThread,
		(char*)CreateThread_hook,
		&m_originalCreateThread, dis);

	if (!m_detourCreateThread->hook()) {
		g_logger.error(sf() << "Error HookCreateProcess : Failed to hook !");
		return false;
	}

	return true;
}
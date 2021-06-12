#include "ProcessProtection.h"

ProcessProtection::ProcessProtection() {
	m_hProcess = GetCurrentProcess();
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

//StackOverflow
bool ProcessProtection::ProtectProcess(HANDLE hProcess) {
    HANDLE handle = m_hProcess;
    if (hProcess) {
        handle = hProcess;
    }

    PACL pEmptyDacl = new ACL;
    ZeroMemory(pEmptyDacl, sizeof(ACL));
    if (!InitializeAcl(pEmptyDacl, sizeof(ACL), ACL_REVISION)) {
        g_logger.error(sf() << "Failed ProtectProcess: InitializeAcl ! Error code : " << GetLastError());
        delete pEmptyDacl;
        return false;
    }
    if (DWORD errCode = SetSecurityInfo(handle, SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION, NULL, NULL, pEmptyDacl, NULL); errCode != ERROR_SUCCESS) {
        g_logger.error(sf() << "Failed ProtectProcess: SetSecurityInfo ! Error code : " << GetLastError());
        delete pEmptyDacl;
        return false;
    }

    delete pEmptyDacl;
    return true;
}
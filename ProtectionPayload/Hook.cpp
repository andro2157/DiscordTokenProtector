#include "Hook.h"
#include "Utils.h"
#include <nlohmann/json.hpp>

#include <unordered_map>
#include <filesystem>
#include <regex>
#include <thread>

#define STATUS_ACCESS_DENIED 0xC0000022

class Hook {
public:
	Hook(HMODULE hModule, std::string procNameStr, PVOID callbackFn, PLH::ADisassembler& dis)
		: m_detour(
			(char*)GetProcAddress(hModule, procNameStr.c_str()),
			(char*)callbackFn,
			&m_original,
			dis
		) {
		if (!m_detour.hook())
			throw std::runtime_error("Failed to hook " + procNameStr);
		std::cout << "Hooked " << procNameStr << std::endl;
	}

	~Hook() {
		m_detour.unHook();//Not really needed since its called on x86Detour's destructor
	}

	uint64_t getOriginal() const { return m_original; }

private:
	PLH::x86Detour m_detour;
	uint64_t m_original;
};

std::unique_ptr<Hook> NtCreateFile_Detour;
std::unique_ptr<Hook> ZwCreateFile_Detour;
std::unique_ptr<Hook> NtQueryAttributesFile_Detour;
std::unique_ptr<Hook> CreateProcessW_Detour;

std::vector<std::wstring> pathsToProtect;

//checks if the provided filename contains the path
bool isProtectedFile(std::wstring filename) {
	for (const auto& path : pathsToProtect) {
		if (filename.find(path) != std::wstring::npos) {//Should be safe since path only have one ":/"
			return true;
		}
	}
	return false;
}

NTSTATUS WINAPI NtCreateFile_hook(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
) {
	std::wstring filename = (LPCWSTR)ObjectAttributes->ObjectName->Buffer;
	if (isProtectedFile(filename)) {
		std::cout << "NtCreateFile : Access denied : " << ws2s(filename) << std::endl;
		return STATUS_ACCESS_DENIED;
	}

	return PLH::FnCast(NtCreateFile_Detour->getOriginal(), &NtCreateFile_hook)(
		FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize,
		FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

NTSTATUS WINAPI ZwCreateFile_hook(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
) {
	std::wstring filename = (LPCWSTR)ObjectAttributes->ObjectName->Buffer;
	if (isProtectedFile(filename)) {
		std::cout << "ZwCreateFile : Access denied : " << ws2s(filename) << std::endl;
		return STATUS_ACCESS_DENIED;
	}

	return PLH::FnCast(ZwCreateFile_Detour->getOriginal(), &ZwCreateFile_hook)(
		FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize,
		FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

NTSTATUS WINAPI NtQueryAttributesFile_hook(
	POBJECT_ATTRIBUTES      ObjectAttributes,
	PVOID/*PFILE_BASIC_INFORMATION*/ FileInformation
) {
	std::wstring filename = (LPCWSTR)ObjectAttributes->ObjectName->Buffer;
	if (isProtectedFile(filename)) {
		std::cout << "NtQueryAttributesFile : Access denied : " << ws2s(filename) << std::endl;
		return STATUS_ACCESS_DENIED;
	}

	return PLH::FnCast(NtQueryAttributesFile_Detour->getOriginal(), &NtQueryAttributesFile_hook)(ObjectAttributes, FileInformation);
}

BOOL WINAPI CreateProcessW_Hook(
	LPCWSTR               lpApplicationName,
	LPWSTR                lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCWSTR               lpCurrentDirectory,
	LPSTARTUPINFOW        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
) {
	if (std::wstring(lpCommandLine).find(L"https://discord.com/handoff") != std::wstring::npos) {
		const std::regex handoffURLRegex(R"a(https:\/\/discord\.com\/handoff\?rpc=([0-9]{1,5})&key=([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}))a");
		std::string commandLine = ws2s(lpCommandLine);
		std::cout << commandLine << std::endl;

		std::smatch matches;
		if (std::regex_search(commandLine, matches, handoffURLRegex) && matches.size() >= 3) {
			using nlohmann::json;

			json msg;
			msg["code"] = "HANDOFF";
			msg["handoff"]["port"] = matches[1];
			msg["handoff"]["key"] = matches[2];

			//std::cout << msg.dump(4) << std::endl;

			server->Send(msg.dump());
		}
		return TRUE;
	}

	return PLH::FnCast(CreateProcessW_Detour->getOriginal(), &CreateProcessW_Hook)
		(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

void SetupHook() {
	pathsToProtect.push_back(getAppDataPathW() + L"\\discord\\Local Storage\\");
	pathsToProtect.push_back(getAppDataPathW() + L"\\discord\\Session Storage\\");
	pathsToProtect.push_back(getAppDataPathW() + L"\\discordcanary\\Local Storage\\");
	pathsToProtect.push_back(getAppDataPathW() + L"\\discordcanary\\Session Storage\\");

	PLH::ErrorLog::singleton().setLogLevel(PLH::ErrorLevel::INFO);

	PLH::CapstoneDisassembler dis(PLH::Mode::x86);

	auto WaitUntilGetModuleHandle = [](std::wstring moduleName) {
		HMODULE hModule = nullptr;
		while (true) {
			hModule = GetModuleHandleW(moduleName.c_str());
			if (hModule)
				break;
			else
				std::this_thread::sleep_for(std::chrono::milliseconds(200));
		}

		return hModule;
	};

	HMODULE hNTDLL = WaitUntilGetModuleHandle(L"ntdll.dll");
	HMODULE hKERNELBASE = WaitUntilGetModuleHandle(L"KernelBase.dll");

	//std::cout << "hNTDLL : " << hNTDLL << std::endl;
	//std::cout << "hKERNELBASE : " << hKERNELBASE << std::endl;

	try {
		NtCreateFile_Detour = std::make_unique<Hook>(hNTDLL, "NtCreateFile", &NtCreateFile_hook, dis);
		ZwCreateFile_Detour = std::make_unique<Hook>(hNTDLL, "ZwCreateFile", &ZwCreateFile_hook, dis);
		NtQueryAttributesFile_Detour = std::make_unique<Hook>(hNTDLL, "NtQueryAttributesFile", &NtQueryAttributesFile_hook, dis);
		CreateProcessW_Detour = std::make_unique<Hook>(hKERNELBASE, "CreateProcessW", &CreateProcessW_Hook, dis);
	}
	catch (std::exception& e) {
		std::cout << e.what() << std::endl;
		RemoveHook();
	}

	CloseHandle(hNTDLL);
	CloseHandle(hKERNELBASE);
}

void RemoveHook() {
	NtCreateFile_Detour.release();
	ZwCreateFile_Detour.release();
	NtQueryAttributesFile_Detour.release();
	CreateProcessW_Detour.release();
}
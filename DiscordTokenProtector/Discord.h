#pragma once
#include "Includes.h"
#include <regex>
#include "Utils/Utils.h"
#include "Crypto/Crypto.h"

enum class DiscordType {
	None,
	Discord,
	DiscordCanary
};

class Discord {
private:
	typedef LONG(NTAPI* NtResumeProcess)(HANDLE ProcessHandle);
	typedef LONG(NTAPI* NtSuspendProcess)(HANDLE ProcessHandle);

public:
	//Throws exception if Discord is not found!
	Discord();

	void searchDiscord();
	static bool isValidDiscordModule(std::wstring path);

	static DiscordType killDiscord(bool fast = false, bool wait = true);//Fast : doesn't check digital signature
	DiscordType isDiscordRunning(bool fast = false, bool suspend = false);

	//Throws exception!
	//Returns the handle of the main thread
	PROCESS_INFORMATION startSuspendedDiscord(DiscordType type);

	DWORD getDiscordPID(DiscordType type, bool fast = false, bool suspend = false);
	static void injectPayload(PROCESS_INFORMATION pInfo, size_t port = 0);

	bool suspendDiscord(DiscordType type, bool suspend);

	static WORD getDiscordRPCPort();
	static bool AcceptHandoff(const std::string& port, const std::string& key, const secure_string& token);
	static std::string getUserInfo(const secure_string& token);
	static secure_string getStoredToken(bool verify);
private:
	static std::wstring getLocal();
	static std::vector<DWORD> getProcessIDbyName(std::wstring process_name);

	std::wstring m_discordPath;
	std::wstring m_discordCanaryPath;

	NtSuspendProcess pfnNtSuspendProcess;
	NtResumeProcess pfnNtResumeProcess;
};

inline std::unique_ptr<Discord> g_discord;
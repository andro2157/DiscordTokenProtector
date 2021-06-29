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

//No need to store more info
struct DiscordUserInfo {
	std::string fullUsername = "";//username#discriminator
	std::string username = "";
	std::string discriminator = "";
	std::string id = "";
	bool mfa = false;
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
	static DiscordUserInfo getUserInfo(const secure_string& token);
	static secure_string getStoredToken(bool verify);

	//error = token if it is successfull
	static bool changePassword(
		const secure_string& token,
		const secure_string& currentPassword,
		const secure_string& newPassword,
		const secure_string& mfaCode,
		secure_string& error);

	std::wstring getDiscordPath(DiscordType type) {
		return (type == DiscordType::Discord) ? m_discordPath : (type == DiscordType::DiscordCanary) ? m_discordCanaryPath : L"";
	}
	std::wstring getDiscordModulePath(DiscordType type) {
		return (type == DiscordType::Discord) ? m_discordModulePath : 
			(type == DiscordType::DiscordCanary) ? m_discordCanaryModulePath : L"";
	}
	std::string getDiscordVersion(DiscordType type) {
		return (type == DiscordType::Discord) ? m_discordVersion : (type == DiscordType::DiscordCanary) ? m_discordCanaryVersion : "";
	}

private:
	static std::wstring getLocal();
	static std::vector<DWORD> getProcessIDbyName(std::wstring process_name);

	std::wstring m_discordPath;
	std::wstring m_discordModulePath;
	std::string m_discordVersion;

	std::wstring m_discordCanaryPath;
	std::wstring m_discordCanaryModulePath;
	std::string m_discordCanaryVersion;

	NtSuspendProcess pfnNtSuspendProcess;
	NtResumeProcess pfnNtResumeProcess;
};

inline std::unique_ptr<Discord> g_discord;
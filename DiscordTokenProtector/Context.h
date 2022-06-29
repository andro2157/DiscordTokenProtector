#pragma once
#include "Includes.h"
#include "Discord.h"
#include "Storage/SecureKV.h"
#include "Protection/FolderRemover.h"
#include "Protection/ProcessProtection.h"
#include "Protection/IntegrityCheck.h"
#include "Network/NetworkManager.h"

enum class State {
	None,
	NoToken,
	InvalidHWID,
	DiscoveredToken,
	MakeNewPassword,
	RequirePassword,
	TokenSecure,
	GetUserInfoError,
};

enum class ProtectionStates {
	Idle,
	Starting,
	Checking,
	CheckIssues,
	Injecting,
	Connected,
	LoggedIn,
	Stop,
	Restart
};

constexpr auto AUTOSTART_LNK = L"Discord Token Protector.lnk";

//TODO make cpp file & remove inlines xd
class Context {
public:
	Context()
		: remover_LocalStorage(getAppDataPathW() + L"\\discord\\Local Storage\\leveldb\\"),
		remover_SessionStorage(getAppDataPathW() + L"\\discord\\Session Storage\\"),
		remover_canary_LocalStorage(getAppDataPathW() + L"\\discordcanary\\Local Storage\\leveldb\\"),
		remover_canary_SessionStorage(getAppDataPathW() + L"\\discordcanary\\Session Storage\\")
	{
		m_isAutoStarting = isAutoStarting();
	}

	void startProtection();
	void stopProtection();

	void initTokenState();

	void installAutoStart();
	void uninstallAutoStart();

	bool isAutoStarting();

	std::string getCurrentStateString();

	//TODO getter setter ?

	State state = State::None;
	ProtectionStates m_protectionState = ProtectionStates::Idle;

	EncryptionType encryptionType_cache = EncryptionType::Unknown;//TODO remove this
	KeyData kd;

	FolderRemover remover_LocalStorage;
	FolderRemover remover_SessionStorage;

	FolderRemover remover_canary_LocalStorage;
	FolderRemover remover_canary_SessionStorage;

	IntegrityCheck integrityCheck;

	std::atomic_bool m_running = false;
	std::atomic_bool m_starting = false;
	std::atomic_bool m_stopping = false;
	std::mutex m_threadMutex;

	bool m_isAutoStarting = false;

	std::string m_currentDiscordID;
private:
	std::thread m_protectionThread;
	std::thread m_networkHandlerThread;


	NetworkManager m_networkManager;

	void networkHandler();

	void protectionThread();
};

inline Context g_context;
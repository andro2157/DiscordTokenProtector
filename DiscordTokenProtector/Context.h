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

};

enum class ProtectionStates {
	Idle,
	Starting,
	Checking,
	CheckIssues,
	Injecting,
	Connected,
	Stop
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

	inline void startProtection() {
		std::lock_guard<std::mutex> lock(m_threadMutex);

		if (m_running) {
			g_logger.warning("Tried to start the protection when it\'s already running.");
			return;
		}

		if (m_protectionThread.joinable()) m_protectionThread.join();

		m_protectionThread = std::thread(&Context::protectionThread, this);
		m_running = true;
	}

	inline void stopProtection() {
		std::lock_guard<std::mutex> lock(m_threadMutex);

		if (!m_running) {
			g_logger.warning("Tried to stop the protection when it\'s already stopped.");
			return;
		}

		m_protectionState = ProtectionStates::Stop;
		Discord::killDiscord();
		m_running = false;

		m_protectionThread.join();
	}

	inline void initTokenState() {
		auto discoverToken = [this](bool hwid = false) {
			secure_string token = Discord::getStoredToken(true);
			if (token.empty() || Discord::getUserInfo(token).id.empty()) {//TODO invalid token message
				this->state = hwid ? State::InvalidHWID : State::NoToken;
			}
			else if (hwid) {
				g_secureKV->write("token", token, HWID_kd);
				kd = HWID_kd;
				this->state = State::TokenSecure;
			} else {				
				this->state = State::DiscoveredToken;
			}
		};

		encryptionType_cache = g_secureKV->getEncryptionType();
		if (encryptionType_cache == EncryptionType::Unknown) {
			discoverToken();
			return;
		}

		if (encryptionType_cache == EncryptionType::HWID) {
			secure_string token = g_secureKV->read("token", HWID_kd);
			if (token.empty() || Discord::getUserInfo(token).id.empty()) {
				discoverToken(true);
			}
			else {
				kd = HWID_kd;
				state = State::TokenSecure;

				if (g_config->read<bool>("auto_start"))
					startProtection();
			}
		}
		else {
			state = State::RequirePassword;
		}
	}

	void installAutoStart() {
#ifndef DISABLE_AUTOSTART
		if (isAutoStarting()) uninstallAutoStart();

		auto startup = getStartupPath();
		if (startup.empty()) return;

#ifdef _PROD
		CreateLink(
			(Config::getConfigPath() + L"\\DiscordTokenProtector.exe").c_str(),
			(startup + L"\\" + AUTOSTART_LNK).c_str(),
			Config::getConfigPath().c_str(),
			L"Discord Token Protector Autostart");
#endif
#endif
	}

	void uninstallAutoStart() {
#ifndef DISABLE_AUTOSTART
		auto startup = getStartupPath();
		if (startup.empty()) return;
		try {
			std::filesystem::remove(startup + L"\\" + AUTOSTART_LNK);
		}
		catch (std::exception& e) {
			g_logger.error(sf() << "Failed to uninstall autostart : " << e.what());
		}
#endif
	}

	bool isAutoStarting() {
#ifndef DISABLE_AUTOSTART
		auto startup = getStartupPath();
		if (startup.empty()) return false;
		//TODO resolve the shortcut to make sure that it's DTP
		return std::filesystem::exists(startup + L"/" + AUTOSTART_LNK);
#else
		return false;
#endif
	}

	std::string getCurrentStateString() {
		static const std::map<ProtectionStates, std::string> stateStrings = {
			{ProtectionStates::Idle, "Waiting for Discord..."},
			{ProtectionStates::Starting, "Starting..."},
			{ProtectionStates::Checking, "Checking the integrity of Discord."},
			{ProtectionStates::CheckIssues, "Found issues."},
			{ProtectionStates::Injecting, "Injecting payload..."},
			{ProtectionStates::Connected, "Connected!"},
			{ProtectionStates::Stop, "Stopping..."}
		};

		return stateStrings.find(m_protectionState)->second;
	}

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
	std::mutex m_threadMutex;

	bool m_isAutoStarting = false;
private:
	std::thread m_protectionThread;
	std::thread m_networkHandlerThread;


	NetworkManager m_networkManager;

	inline void networkHandler() {
		using nlohmann::json;

		while (m_protectionState == ProtectionStates::Connected) {
			try {
				std::string msg = m_networkManager.Recv();
				if (msg == "KeepAlive") continue;

				json jsonMsg = json::parse(msg);

				if (jsonMsg["code"] == "HANDOFF") {
					if (!Discord::AcceptHandoff(jsonMsg["handoff"]["port"], jsonMsg["handoff"]["key"], g_secureKV->read("token", kd))) {
						MessageBoxA(NULL, "Failed to accept handoff. The token is most likely invalid. Please check the logs for more detail.",
							"Discord Token Protector", MB_ICONSTOP | MB_OK);
						g_secureKV->reopenFile(true);
						ExitProcess(0);
					}
				}
			}
			catch (std::exception& e) {
				g_logger.error(sf() << __FUNCSIG__ " : " << e.what());
				//Wait a bit, Discord might be closing...
				std::this_thread::sleep_for(std::chrono::milliseconds(1000));
				break;
			}
		}
		m_protectionState = ProtectionStates::Stop;
	}

	inline void protectionThread() {
		bool hasStartedDiscord = false;
		bool autoStart = g_config->read<bool>("auto_start_discord");

		constexpr auto DELAY = 250;

		auto startRemovers = [this]() {
			remover_LocalStorage.Start();
			remover_SessionStorage.Start();
			remover_canary_LocalStorage.Start();
			remover_canary_SessionStorage.Start();
		};

		auto stopRemovers = [this]() {
			remover_LocalStorage.Stop();
			remover_SessionStorage.Stop();
			remover_canary_LocalStorage.Stop();
			remover_canary_SessionStorage.Stop();
		};

		startRemovers();

		while (m_running) {
			if (m_protectionState == ProtectionStates::Injecting) {//Uh this shouldn't happen
				g_logger.warning("Unexpected m_protectionState : Injecting.");
				m_protectionState = ProtectionStates::Stop;
			}

			if (m_protectionState == ProtectionStates::Connected) {
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
				continue;
			}

			if (m_protectionState == ProtectionStates::Stop) {
				m_networkManager.Stop();
				Discord::killDiscord();

				m_protectionState = ProtectionStates::Idle;
				startRemovers();
				continue;
			}

			DiscordType discordType = g_discord->isDiscordRunning(false, true);

			if (m_protectionState == ProtectionStates::Idle &&
				(discordType != DiscordType::None || autoStart && !hasStartedDiscord)) {
				if (discordType == DiscordType::None) {//With the autoStart Discord might not be running
					discordType = DiscordType::Discord;
				}

				m_protectionState = ProtectionStates::Starting;
				hasStartedDiscord = true;

				stopRemovers();

				if (m_protectionState == ProtectionStates::Stop) continue;

				Discord::killDiscord();
				remover_LocalStorage.Remove();
				remover_canary_LocalStorage.Remove();

				//Check before launching!
				if (g_config->read<bool>("integrity")) {
					m_protectionState = ProtectionStates::Checking;
					if (m_protectionState == ProtectionStates::Stop) continue;

					integrityCheck.setCheckHash(g_config->read<bool>("integrity_checkhash"));
					integrityCheck.setCheckExecutableSig(g_config->read<bool>("integrity_checkexecutable"));
					integrityCheck.setCheckModule(g_config->read<bool>("integrity_checkmodule"));
					integrityCheck.setCheckResources(g_config->read<bool>("integrity_checkresource"));
					integrityCheck.setCheckScripts(g_config->read<bool>("integrity_checkscripts"));
					integrityCheck.setAllowBetterDiscord(g_config->read<bool>("integrity_allowbetterdiscord"));
					integrityCheck.setRedownloadHashes(g_config->read<bool>("integrity_redownloadhashes"));

					integrityCheck.setDiscordVersion(g_discord->getDiscordVersion(discordType));

					if (!integrityCheck.check(ws2s(g_discord->getDiscordPath(discordType)))) {
						m_protectionState = ProtectionStates::CheckIssues;

						//Wait for the user...
						while (m_protectionState == ProtectionStates::CheckIssues) {
							std::this_thread::sleep_for(std::chrono::milliseconds(100));
						}

						//Cancel!
						if (m_protectionState == ProtectionStates::Stop)
							continue;
					}
				}

				if (m_protectionState == ProtectionStates::Stop) continue;

				m_protectionState = ProtectionStates::Injecting;

				PROCESS_INFORMATION discordProcess = g_discord->startSuspendedDiscord(discordType);//TODO CloseHandle?
				//g_processprotection->ProtectProcess(discordProcess.hProcess);//TODO Fix

				//TODO make this thing async
				try {
					if (m_protectionState == ProtectionStates::Stop) continue;

					std::promise<USHORT> portPromise;

					auto start = std::async(std::launch::async, &NetworkManager::Start, &m_networkManager, std::ref(portPromise));
					USHORT port = portPromise.get_future().get();//Wait until it gets the port

					std::cout << "injectPayload : " << port << std::endl;

					Discord::injectPayload(discordProcess, port);

					std::cout << "Injected!" << std::endl;

					if (m_protectionState == ProtectionStates::Stop) continue;

					if (ResumeThread(discordProcess.hThread) == -1)
						throw std::runtime_error(sf() << "Failed ResumeThread : " << GetLastError());

					//Wait for the payload client
					for (int i = 0; (i < 60 * 10 && m_protectionState != ProtectionStates::Stop); i++) {//Wait 60 seconds
						if (start.wait_for(std::chrono::milliseconds(100)) == std::future_status::ready)
							break;
					}

					if (start.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) {
						throw std::exception(("Discord payload timeout!"));
					}

					if (m_protectionState == ProtectionStates::Stop) continue;

					std::cout << "Finish!" << std::endl;

					if (start.valid())
						start.get();//gets the exception (if there's one)

					if (m_networkManager.Recv() != "LOADED") {
						throw std::exception("Invalid payload response");
					}
					
					//Bruteforce way, it works but well...
					//for (int i = 0; i < 30; i++) {//30 seconds timeout
					//	WORD port = Discord::getDiscordRPCPort();
					//	if (port != 0) {
					//		if (Discord::AcceptHandoff(
					//			std::to_string(port),
					//			"key"/*we can put anything here actually*/,
					//			g_secureKV->read("token", kd)
					//		)) {
					//			MessageBoxA(NULL, "Failed to accept handoff. The token is most likely invalid. Please check the logs for more detail.",
					//				"Discord Token Protector", MB_ICONSTOP | MB_OK);
					//			g_secureKV->reopenFile(true);
					//			ExitProcess(0);
					//		}
					//		break;
					//	}
					//	std::this_thread::sleep_for(std::chrono::seconds(1));
					//}

					m_protectionState = ProtectionStates::Connected;

					if (m_networkHandlerThread.joinable()) m_networkHandlerThread.join();

					m_networkHandlerThread = std::thread(&Context::networkHandler, this);
				}
				catch (std::exception& e) {
					g_logger.error(sf() << __FUNCSIG__ " : Failed to load payload : " << e.what());
					m_protectionState = ProtectionStates::Stop;
					continue;
				}
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(DELAY));
		}

		m_protectionState = ProtectionStates::Idle;
		if (m_networkHandlerThread.joinable()) m_networkHandlerThread.join();

		stopRemovers();
	}
};

inline Context g_context;
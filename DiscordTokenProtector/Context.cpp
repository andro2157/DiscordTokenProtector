#include "Context.h"
#include "Storage/TokenManager.h"

void Context::startProtection() {
	std::lock_guard<std::mutex> lock(m_threadMutex);

	if (m_stopping) {
		g_logger.warning("Tried to stop the protection while it\'s stopping.");
		return;
	}

	if (m_running || m_starting) {
		g_logger.warning("Tried to start the protection when it\'s already running.");
		return;
	}

	m_starting = true;

	if (m_protectionThread.joinable()) m_protectionThread.join();

	m_running = true;

	m_protectionThread = std::thread(&Context::protectionThread, this);

	m_starting = false;
}

void Context::stopProtection() {
	std::lock_guard<std::mutex> lock(m_threadMutex);

	if (m_starting) {
		g_logger.warning("Tried to stop the protection while it\'s starting.");
		return;
	}

	if (!m_running || m_stopping) {
		g_logger.warning("Tried to stop the protection when it\'s already stopped.");
		return;
	}
	m_stopping = true;

	m_protectionState = ProtectionStates::Stop;
	Discord::killDiscord();

	m_protectionThread.join();

	m_stopping = false;
}

void Context::initTokenState() {
	//auto discoverToken = [this](bool hwid = false) {
	//	try {
	//		secure_string token = g_discord->getMemoryToken(true);

	//		Discord::getUserInfo(token);//TODO invalid token message

	//		if (hwid) {
	//			g_secureKV->write("token", token, HWID_kd);
	//			kd = HWID_kd;
	//			this->state = State::TokenSecure;
	//		}
	//		else {
	//			this->state = State::DiscoveredToken;
	//		}
	//	}
	//	catch (std::exception& e) {
	//		g_logger.warning(sf() << "in initTokenState : " << e.what());
	//		this->state = hwid ? State::InvalidHWID : State::NoToken;
	//	}
	//};

	encryptionType_cache = g_secureKV->getEncryptionType();
	if (encryptionType_cache == EncryptionType::Unknown) {
		//discoverToken();
		this->state = State::NoToken;
		return;
	}

	if (encryptionType_cache == EncryptionType::HWID) {
		kd = HWID_kd;

		try {
			g_tokenManager.init();

			secure_string token = g_tokenManager.getCurrentToken();
			g_tokenManager.updateCurrentCachedInfo(g_discord->getUserInfo(token));
		}
		//catch (invalid_token_exception& e) {
		//	discoverToken(true);
		//}
		catch (...) {
			state = State::GetUserInfoError;
		}

		state = State::TokenSecure;

		if (g_config->read<bool>("auto_start"))
			startProtection();
	}
	else {
		state = State::RequirePassword;
	}
}

void Context::installAutoStart() {
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

void Context::uninstallAutoStart() {
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

bool Context::isAutoStarting() {
#ifndef DISABLE_AUTOSTART
	auto startup = getStartupPath();
	if (startup.empty()) return false;
	//TODO resolve the shortcut to make sure that it's DTP
	return std::filesystem::exists(startup + L"/" + AUTOSTART_LNK);
#else
	return false;
#endif
}

std::string Context::getCurrentStateString() {
	static const std::map<ProtectionStates, std::string> stateStrings = {
		{ProtectionStates::Idle, "Waiting for Discord..."},
		{ProtectionStates::Starting, "Starting..."},
		{ProtectionStates::Checking, "Checking the integrity of Discord."},
		{ProtectionStates::CheckIssues, "Found issues."},
		{ProtectionStates::Injecting, "Injecting payload..."},
		{ProtectionStates::Connected, "Logging in..."},
		{ProtectionStates::LoggedIn, "Logged in!"},
		{ProtectionStates::Stop, "Stopping..."},
		{ProtectionStates::Restart, "Restarting Discord..."}
	};

	return stateStrings.find(m_protectionState)->second;
}

void Context::networkHandler() {
	using nlohmann::json;

	std::once_flag discordSecurityInfo;

	while (m_protectionState == ProtectionStates::Connected ||
		m_protectionState == ProtectionStates::LoggedIn) {
		try {
			std::string msg = m_networkManager.Recv();
			if (msg == "KeepAlive") continue;

			json jsonMsg = json::parse(msg);

			if (jsonMsg["code"] == "HANDOFF") {
				m_currentDiscordID = g_tokenManager.getCurrentCachedInfo().id;
				if (!Discord::AcceptHandoff(jsonMsg["handoff"]["port"], jsonMsg["handoff"]["key"], g_tokenManager.getCurrentToken())) {
					MessageBoxA(NULL, "Failed to accept handoff. The token is most likely invalid. Please check the logs for more detail.",
						"Discord Token Protector", MB_ICONSTOP | MB_OK);
					
					g_tokenManager.removeToken(g_tokenManager.getCurrentIndex());
					if (g_tokenManager.size() == 0) {
						g_secureKV->reopenFile(true);
						ExitProcess(0);
					}
					else {
						m_protectionState = ProtectionStates::Stop;
					}
				}

				if (g_secureKV->read_int("protect_discord_process", kd, DEFAULT_KV::protect_discord_process)) {
					std::call_once(discordSecurityInfo, []() {
						g_discord->setDiscordSecurityInfo(DiscordType::Discord);
						g_logger.info("set Discord security info!");
						});
				}

				m_protectionState = ProtectionStates::LoggedIn;
			}
		}
		catch (std::exception& e) {
			g_logger.error(sf() << __FUNCSIG__ " : " << e.what());
			//Wait a bit, Discord might be closing...
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
			break;
		}
	}

	if (m_protectionState != ProtectionStates::Restart)
		m_protectionState = ProtectionStates::Stop;
}

void Context::protectionThread() {
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

		if (m_protectionState == ProtectionStates::Connected ||
			m_protectionState == ProtectionStates::LoggedIn) {
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			continue;
		}

		if (m_protectionState == ProtectionStates::Stop) {
			m_networkManager.Stop();
			Discord::killDiscord();//Might not be able to terminate if the process protection is enabled

			while (g_discord->isDiscordRunning(false, false) != DiscordType::None) {
				std::this_thread::sleep_for(std::chrono::milliseconds(500));
			}

			if (m_networkHandlerThread.joinable()) m_networkHandlerThread.join();

			m_protectionState = ProtectionStates::Idle;

			if (m_stopping)
				m_running = false;
			else
				startRemovers();
			continue;
		}

		if (m_protectionState == ProtectionStates::Restart) {
			m_networkManager.Stop();
			Discord::killDiscord();

			while (g_discord->isDiscordRunning(false, false) != DiscordType::None) {
				std::this_thread::sleep_for(std::chrono::milliseconds(500));
			}

			if (m_networkHandlerThread.joinable()) m_networkHandlerThread.join();
		}

		DiscordType discordType = g_discord->isDiscordRunning(false, true);

		if ((m_protectionState == ProtectionStates::Idle &&
			(discordType != DiscordType::None || autoStart && !hasStartedDiscord)) ||
			m_protectionState == ProtectionStates::Restart) {
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
			if (g_secureKV->read_int("integrity", kd, DEFAULT_KV::integrity)) {
				m_protectionState = ProtectionStates::Checking;
				if (m_protectionState == ProtectionStates::Stop) continue;

				integrityCheck.setCheckHash(g_secureKV->read_int("integrity_checkhash", kd, DEFAULT_KV::integrity_checkhash));
				integrityCheck.setCheckExecutableSig(g_secureKV->read_int("integrity_checkexecutable", kd, DEFAULT_KV::integrity_checkexecutable));
				integrityCheck.setCheckModule(g_secureKV->read_int("integrity_checkmodule", kd, DEFAULT_KV::integrity_checkmodule));
				integrityCheck.setCheckResources(g_secureKV->read_int("integrity_checkresource", kd, DEFAULT_KV::integrity_checkresource));
				integrityCheck.setCheckScripts(g_secureKV->read_int("integrity_checkscripts", kd, DEFAULT_KV::integrity_checkscripts));
				integrityCheck.setAllowBetterDiscord(g_secureKV->read_int("integrity_allowbetterdiscord", kd, DEFAULT_KV::integrity_allowbetterdiscord));
				integrityCheck.setRedownloadHashes(g_secureKV->read_int("integrity_redownloadhashes", kd, DEFAULT_KV::integrity_redownloadhashes));
				integrityCheck.setIgnoreNonExecAssets(g_secureKV->read_int("integrity_ignorenonexec", kd, DEFAULT_KV::integrity_ignorenonexec));

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

			//TODO make this thing async
			try {
				PROCESS_INFORMATION discordProcess = g_discord->startSuspendedDiscord(discordType);//TODO CloseHandle?
				//g_processprotection->ProtectProcess(discordProcess.hProcess);//TODO Fix

				if (m_protectionState == ProtectionStates::Stop) continue;

				std::promise<USHORT> portPromise;

				auto start = std::async(std::launch::async, &NetworkManager::Start, &m_networkManager, std::ref(portPromise));
				USHORT port = portPromise.get_future().get();//Wait until it gets the port

				std::cout << "injectPayload : " << port << std::endl;

				Discord::injectPayload(discordProcess, port);

				std::cout << "Injected!" << std::endl;

				if (m_protectionState == ProtectionStates::Stop) continue;

				if (ResumeThread(discordProcess.hThread) == -1) {
					throw std::runtime_error(sf() << "Failed ResumeThread : " << GetLastError());
				}

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
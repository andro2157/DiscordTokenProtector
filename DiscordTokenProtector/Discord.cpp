#include "shlobj.h"
#include <tlhelp32.h>
#include <winternl.h>
#include <future>

#include "Discord.h"
#include "Protection/FileCert.h"
#include "Utils/CurlUtils.h"
#include "Utils/Utils.h"

#include <nlohmann/json.hpp>

uintptr_t GetModuleBaseAddress(DWORD procId, const char* modName);
uintptr_t GetProcAddressEx(HANDLE hProcess, DWORD pid, const char* module, const char* function);

Discord::Discord() {
	searchDiscord();
	if (m_discordModulePath.empty() && m_discordCanaryModulePath.empty()) throw std::runtime_error("Unable to find discord! Is it installed?");

	pfnNtSuspendProcess = reinterpret_cast<NtSuspendProcess>(GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtSuspendProcess"));
	if (pfnNtSuspendProcess == nullptr) throw std::runtime_error("NtSuspendProcess was null");

	pfnNtResumeProcess = reinterpret_cast<NtResumeProcess>(GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtResumeProcess"));
	if (pfnNtResumeProcess == nullptr) throw std::runtime_error("NtResumeProcess was null");
}

void Discord::searchDiscord() {
	auto searchBestDiscordVersion = [](std::wstring path, std::wstring moduleName,
		std::wstring& discordPath, std::wstring& modulePath, std::string& discordVersion) {

		UINT BestMajor = 0;
		UINT BestMinor = 0;
		UINT BestPatch = 0;

		try {
			for (auto& p : std::filesystem::directory_iterator(path)) {
				std::wstring path = p.path().wstring();
				std::wstring filename = p.path().filename().wstring();

				if (auto appPos = filename.find(L"app-"); p.is_directory() && appPos == 0) {//A directory that starts with "app-"
					if (!std::filesystem::exists(path + L"\\" + moduleName))
						continue;

					//Get the version from the folder
					std::wstring version = filename.substr(4);

					bool valid_version = true;
					for (auto c : version) {
						if (!std::isdigit(c) && c != L'.')
							valid_version = false;
					}

					if (!valid_version)
						continue;

					auto firstDot = version.find_first_of(L'.');
					if (firstDot == std::wstring::npos)
						continue;

					auto secondDot = version.find_last_of(L'.');
					if (secondDot == std::wstring::npos)
						continue;

					UINT Major = std::stoi(version.substr(0, firstDot));
					UINT Minor = std::stoi(version.substr(firstDot + 1, secondDot - firstDot - 1));
					UINT Patch = std::stoi(version.substr(secondDot + 1));

					if (Major > BestMajor || Minor > BestMinor || Patch > BestPatch) {
						BestMajor = Major;
						BestMinor = Minor;
						BestPatch = Patch;

						discordPath = path;
						modulePath = path + L"\\" + moduleName;
						discordVersion = ws2s(version);
					}
				}
			}
		}
		catch (std::exception& e) {
			g_logger.warning(sf() << "Failed to find Discord in " << ws2s(path) << " : " << e.what());
		}

		if (modulePath.empty() || !isValidDiscordModule(modulePath)) {
			modulePath.clear();
		}
	};

	searchBestDiscordVersion(
		getLocal() + L"\\Discord\\", L"Discord.exe",
		m_discordPath,
		m_discordModulePath,
		m_discordVersion
	);

	searchBestDiscordVersion(
		getLocal() + L"\\DiscordCanary\\", L"DiscordCanary.exe",
		m_discordCanaryPath,
		m_discordCanaryModulePath,
		m_discordCanaryVersion
	);
}

bool Discord::isValidDiscordModule(std::wstring path) {
	return VerifyEmbeddedSignature(path.c_str()) && VerifySignatureIssuer(path, L"Discord Inc.");
}

DiscordType Discord::killDiscord(bool fast, bool wait) {
	DiscordType status = DiscordType::None;

	std::vector<DWORD> pids = getProcessIDbyName(L"Discord.exe");
	std::vector<DWORD> canary_pids = getProcessIDbyName(L"DiscordCanary.exe");

	auto killDiscordPids = [fast, wait](const std::vector<DWORD>& pids) {
		bool killed = false;
		std::vector<std::future<void>> asyncWaits;

		for (DWORD pid : pids) {
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, pid);//TODO remove PROCESS_QUERY_INFORMATION for the fast one ?
			if (hProcess == NULL) {
				g_logger.error(sf() << __FUNCSIG__ " : Failed to open process. pid : " << pid);
				continue;
			}

			if (!fast) {
				DWORD pathSize = MAX_PATH;
				WCHAR processPath[MAX_PATH];

				if (!QueryFullProcessImageNameW(hProcess, NULL, processPath, &pathSize)) {
					g_logger.error(sf() << __FUNCSIG__ " : Failed to get process info. pid : " << pid);
					continue;
				}

				if (!isValidDiscordModule(processPath))
					continue;
			}

			if (TerminateProcess(hProcess, 0)) {
				killed = true;
				if (wait) {
					asyncWaits.push_back(std::async(std::launch::async, [&hProcess, pid]() {
						WaitForSingleObject(hProcess, INFINITE);
						g_logger.info(sf() << __FUNCSIG__ " : Terminated process. pid : " << pid);
						CloseHandle(hProcess);
					}));
				}
			}
			else {
				g_logger.error(sf() << __FUNCSIG__ " : Failed to terminate process. pid : " << pid);
			}
			if (!wait)
				CloseHandle(hProcess);
		}

		for (auto& task : asyncWaits) {
			task.get();
		}

		return killed;
	};

	if (killDiscordPids(pids)) status = DiscordType::Discord;
	if (killDiscordPids(canary_pids)) status = DiscordType::DiscordCanary;//If both : Canary
	
	return status;
}

DiscordType Discord::isDiscordRunning(bool fast, bool suspend) {
	if (getDiscordPID(DiscordType::DiscordCanary, fast, suspend)) return DiscordType::DiscordCanary;
	if (getDiscordPID(DiscordType::Discord, fast, suspend)) return DiscordType::Discord;

	return DiscordType::None;
}


PROCESS_INFORMATION Discord::startSuspendedDiscord(DiscordType type) {
	if (type == DiscordType::None) return PROCESS_INFORMATION({ NULL, NULL, NULL, NULL });

	STARTUPINFOW startupInfo;
	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);

	PROCESS_INFORMATION processInfo;
	ZeroMemory(&processInfo, sizeof(processInfo));

	std::wstring processDir = getLocal() + (type == DiscordType::Discord ? L"\\Discord" : L"\\DiscordCanary");

	if (!CreateProcessW(
			NULL,
			const_cast<LPWSTR>((type == DiscordType::Discord ? m_discordModulePath : m_discordCanaryModulePath).c_str()),
			NULL, NULL, FALSE, CREATE_SUSPENDED, NULL,
			const_cast<LPCWSTR>(processDir.c_str()),
			&startupInfo, &processInfo)) {
		throw std::runtime_error(sf() << __FUNCSIG__ " : Failed CreateProcessW : " << GetLastError());
	}

	return processInfo;
}

DWORD Discord::getDiscordPID(DiscordType type, bool fast, bool suspend) {
	if (type == DiscordType::None) return 0;

	auto pids = getProcessIDbyName(type == DiscordType::Discord ? L"Discord.exe" : L"DiscordCanary.exe");

	for (DWORD pid : pids) {
		HANDLE hProcess = OpenProcess(/*PROCESS_QUERY_INFORMATION*/PROCESS_ALL_ACCESS/*to suspend*/, FALSE, pid);
		DWORD pathSize = MAX_PATH;
		WCHAR processPath[MAX_PATH];

		if (hProcess == NULL || !QueryFullProcessImageNameW(hProcess, NULL, processPath, &pathSize)) {
			continue;//Most likely not discord
		}

		DWORD validPid = NULL;
		if (fast) validPid = pid;
		else {
			if (suspend) pfnNtSuspendProcess(hProcess);
			if (isValidDiscordModule(processPath)) validPid = pid;
			else
				pfnNtResumeProcess(hProcess);
		}
		CloseHandle(hProcess);

		if (validPid) return validPid;
	}
	return 0;
}

void Discord::injectPayload(PROCESS_INFORMATION pInfo, size_t port) {
	const static std::string PAYLOADNAME = "ProtectionPayload.dll";

	if (!std::filesystem::exists(PAYLOADNAME)) {//TODO add some checks to this payload
		throw std::runtime_error(__FUNCSIG__ " : Unable to find ProtectionPayload.dll");
	}

	char PayloadPath[MAX_PATH];
	if (!GetFullPathNameA(PAYLOADNAME.c_str(), MAX_PATH, PayloadPath, 0))
		throw std::runtime_error(sf() << __FUNCSIG__ " : Failed GetFullPathNameA : " << GetLastError());

	//DWORD pid = getDiscordPID(type);
	//HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	//if (hProcess == NULL)
	//	throw std::runtime_error(sf() << __FUNCSIG__ " : Failed OpenProcess : " << GetLastError());

	//TODO change to manual mapping?
	HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
	if (!kernel32)
		throw std::runtime_error(__FUNCSIG__ " : Unable to get kernel32.dll");

	FARPROC loadLibrary = GetProcAddress(kernel32, "LoadLibraryA");//TODO LoadLibraryW?
	if (!loadLibrary)
		throw std::runtime_error(__FUNCSIG__ " : Unable to get LoadLibraryA");

	LPVOID dllnameAlloc = VirtualAllocEx(pInfo.hProcess, NULL, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!dllnameAlloc)
		throw std::runtime_error(sf() << __FUNCSIG__ " : Failed VirtualAllocEx (dllnameAlloc) : " << GetLastError());

	if (!WriteProcessMemory(pInfo.hProcess, dllnameAlloc, PayloadPath, MAX_PATH, NULL))
		throw std::runtime_error(sf() << __FUNCSIG__ " : Failed WriteProcessMemory (dllnameAlloc) : " << GetLastError());

	HANDLE loadLibraryThread = CreateRemoteThread(pInfo.hProcess, NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibrary), dllnameAlloc, NULL, NULL);
	if (!loadLibraryThread)
		throw std::runtime_error(sf() << __FUNCSIG__ " : Failed CreateRemoteThread (LoadLibraryA) : " << GetLastError());

	WaitForSingleObject(loadLibraryThread, INFINITE);
	CloseHandle(loadLibraryThread);

	g_logger.info(sf() << "port : " << port);

	if (port != 0) {
		std::this_thread::sleep_for(std::chrono::milliseconds(200));//Just in case

		uintptr_t setPort = GetProcAddressEx(pInfo.hProcess, pInfo.dwProcessId, PAYLOADNAME.c_str(), "setPort");
		if (setPort == NULL)
			throw std::runtime_error(__FUNCSIG__ " : Failed GetProcAddressEx");

		g_logger.info(sf() << "setport : " << setPort);

		HANDLE setPortThread = CreateRemoteThread(pInfo.hProcess, NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(setPort), reinterpret_cast<LPVOID>(port), NULL, NULL);
		if (!setPortThread)
			throw std::runtime_error(sf() << __FUNCSIG__ " : Failed CreateRemoteThread (setPort) : " << GetLastError());

		WaitForSingleObject(setPortThread, INFINITE);
		CloseHandle(setPortThread);
		g_logger.info(sf() << "done");
	}

	//CloseHandle(hProcess);
}

bool Discord::suspendDiscord(DiscordType type, bool suspend) {
	DWORD pid = getDiscordPID(type);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) {
		g_logger.error(sf() << __FUNCSIG__ " : Failed OpenProcess : " << GetLastError());
		return false;
	}

	bool success = true;

	if (suspend) {
		if (pfnNtSuspendProcess(hProcess)) success = false;
	}
	else {
		if (pfnNtResumeProcess(hProcess)) success = false;
	}

	CloseHandle(hProcess);
	return success;
}

std::wstring Discord::getLocal() {
	TCHAR szPath[MAX_PATH];
	if (!SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, szPath)) || wcsstr(szPath, L"AppData\\Local") == nullptr) {
		size_t required_size;
		_wgetenv_s(&required_size, szPath, L"LOCALAPPDATA");//backup method
	}
	return std::wstring(szPath);
}

std::vector<DWORD> Discord::getProcessIDbyName(std::wstring process_name) {
	std::vector<DWORD> process_ids;

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry)) {
		while (Process32Next(snapshot, &entry)) {
			if (!lstrcmpW(entry.szExeFile, process_name.c_str())) {
				process_ids.push_back(entry.th32ProcessID);
			}
		}
	}
	CloseHandle(snapshot);
	return process_ids;
}

WORD Discord::getDiscordRPCPort() {
	//Basically bruteforce 127.0.0.1:port [6463, 6472]
	//https://discord.com/developers/docs/topics/rpc#rpc-server-ports
	//(this is literally the recommendation from the docs)
	using nlohmann::json;

	WORD workingPort = 0;
	for (WORD port = 6463; port <= 6472; port++) {
		try {
			secure_string out;
			cURL_get(sf() << "http://127.0.0.1:" << port, nullptr, out);
			json outJson = json::parse(out);
			if (outJson["code"].get<int>() == 0 && outJson["message"].get<std::string>() == "Not Found") {
				workingPort = port;
				break;
			}
		}
		catch (...) {
			continue;
		}
	}

	return workingPort;
}

bool Discord::AcceptHandoff(const std::string& port, const std::string& key, const secure_string& token) {
	using nlohmann::json;

	try {
		struct curl_slist* chunk = NULL;
		chunk = curl_slist_append(chunk, ("Authorization: " + token).c_str());
		chunk = curl_slist_append(chunk, "Content-Type: application/json");

		json handoffData;
		handoffData["key"] = key;

		secure_string handoffToken;
		cURL_post("https://discord.com/api/v8/auth/handoff", chunk, handoffData.dump().c_str(), handoffToken);
		handoffToken = json::parse(handoffToken)["handoff_token"].get<std::string>();

		chunk = NULL;//Gets freed in cURL_post

		//Without this header we get this error : "code":4000,"message":"No Client ID Specified"... wasted hours of debugging
		chunk = curl_slist_append(chunk, "Origin: https://discord.com");
		chunk = curl_slist_append(chunk, "Content-Type: application/json");

		handoffData.clear();
		handoffData["cmd"] = "BROWSER_HANDOFF";
		handoffData["args"]["handoffToken"] = handoffToken;
		handoffData["nonce"] = getRandomUUID();

		secure_string handoffRPCOut;
		cURL_post("http://127.0.0.1:" + port + "/rpc?v=1", chunk, handoffData.dump().c_str(), handoffRPCOut);
		json rpcResp = json::parse(handoffRPCOut);
		if (rpcResp.contains("code") && rpcResp.contains("message")) {//Error!
			throw std::runtime_error(sf() << "Error " << rpcResp["code"].get<int>() << " : " << rpcResp["message"].get<std::string>());
		}

		g_logger.info("Accepted handoff!");
	}
	catch (const std::exception& e) {
		g_logger.error(sf() << "Failed AcceptHandoff : " << e.what());
		return false;
	}
	return true;
}

DiscordUserInfo Discord::getUserInfo(const secure_string& token) {
	using nlohmann::json;

	try {
		struct curl_slist* chunk = NULL;
		chunk = curl_slist_append(chunk, ("Authorization: " + token).c_str());
		chunk = curl_slist_append(chunk, "Content-Type: application/json");

		secure_string userinfo;
		cURL_get("https://discord.com/api/v9/users/@me", chunk, userinfo);

		json userinfoJSON = json::parse(userinfo);

		if (userinfoJSON.contains("message"))
			throw std::runtime_error(userinfoJSON["message"].get<std::string>());

		return {
			userinfoJSON["username"].get<std::string>() + "#" + userinfoJSON["discriminator"].get<std::string>(),
			userinfoJSON["username"].get<std::string>(),
			userinfoJSON["discriminator"].get<std::string>(),
			userinfoJSON["id"].get<std::string>(),
			userinfoJSON["mfa_enabled"].get<bool>()
		};
	}
	catch (const std::exception& e) {
		g_logger.error(sf() << "Failed getUserInfo : " << e.what());
	}

	return DiscordUserInfo();
}

secure_string Discord::getStoredToken(bool verify) {
	const std::regex tokenRegex(R"reg(ken[^"]{0,32}"([A-z0-9._-]{30,150})")reg");

	std::map<secure_string, size_t> results;

	std::vector<secure_string> invalids;//To avoid duplicate api calls

	auto searchTokenInPath = [&results, &invalids, &tokenRegex, verify](std::wstring path) {
		try {
			if (!std::filesystem::exists(path)) return;

			for (const auto& entry : std::filesystem::directory_iterator(path)) {
				if (entry.path().extension() == L".ldb" || entry.path().extension() == L".log") {
					std::ifstream fileStream(entry.path(), std::ios::binary);//TODO check file size?
					secure_string fileContent((std::istreambuf_iterator<char>(fileStream)), std::istreambuf_iterator<char>());//Copy file to memory
					fileStream.close();

					std::smatch matches;
					//TODO FIX:
					//secure_string is not 0ing matches[1].str()'s content, therefore the token is then still in the memory...
					//But this is only called on setup, so it should be fine, I guess?
					//std::match_results<secure_string::const_iterator, CryptoPP::AllocatorWithCleanup<char>> matches;
					while (std::regex_search(fileContent, matches, tokenRegex)) {
						if (matches.size() > 1) {
							secure_string match(matches[1].str());
							if (results.find(match) == results.end()) {//A new token! let's add it to the list
								if (std::find(invalids.begin(), invalids.end(), match) == invalids.end()) {//If not invalid
									if (verify && getUserInfo(match).id.empty())
										invalids.push_back(match);
									else
										results.insert({ match, 1 });
								}
							}
							else {//Already known!
								results[match] += 1;
							}
						}
						fileContent = secure_string(matches.suffix().str());
					}
				}
			}
		}
		catch (std::exception& e) {
			g_logger.warning(sf() << "Failed to search token in " << ws2s(path) << " : " << e.what());
		}
	};

	searchTokenInPath(getAppDataPathW() + L"\\discord\\Local Storage\\leveldb\\");
	searchTokenInPath(getAppDataPathW() + L"\\discordcanary\\Local Storage\\leveldb\\");

	if (results.empty()) return "";

	return results.rbegin()->first;//Returns the token with the most matches

	return "";
}

bool Discord::changePassword(
	const secure_string& token,
	const secure_string& currentPassword,
	const secure_string& newPassword,
	const secure_string& mfaCode,
	secure_string& error) {

	secure_string patchData;//We're avoiding the json lib to not keep the data in memory

	auto jsonEscape = [](const secure_string& data) {
		secure_string out;
		out.reserve(data.size());

		for (const char c : data) {
			switch (c) {
			case '\b': out += "\\b"; break;
			case '\f': out += "\\f"; break;
			case '\n': out += "\\n"; break;
			case '\r': out += "\\r"; break;
			case '\t': out += "\\t"; break;
			case '\"': out += "\\\""; break;
			case '\\': out += "\\\\"; break;
			default: out += c;  break;
			}
		}

		return out;
	};

	patchData += "{\"password\":\"" + jsonEscape(currentPassword) +
		"\",\"new_password\":\"" + jsonEscape(newPassword) + "\"";

	if (!mfaCode.empty()) {
		patchData += ",\"code\":\"" + jsonEscape(mfaCode) + "\"";
	}

	patchData += "}";

	try {
		struct curl_slist* chunk = NULL;
		chunk = curl_slist_append(chunk, ("Authorization: " + token).c_str());
		chunk = curl_slist_append(chunk, "Content-Type: application/json");
		chunk = curl_slist_append(chunk, "Accept-Language: en-US");

		secure_string output;
		cURL_post("https://discord.com/api/v9/users/@me", chunk, patchData, output, "PATCH");

		//To avoid using json or regex (insecure)
		auto getStringKey = [](const secure_string& data, secure_string key) {
			key = "\"" + key + "\": \"";
			size_t pos = data.find(key);
			if (pos == secure_string::npos) return secure_string();

			size_t endPos = pos + key.size();
			while (true) {
				endPos = data.find("\"", endPos);
				if (endPos == secure_string::npos) return secure_string();
				if (data[endPos - 1] == '\\') {
					++endPos;
					continue;
				}
				break;
			}

			return data.substr(pos + key.size(), endPos - pos - key.size());
		};

		//Requires 2FA!
		if (auto pos = output.find("\"code\": 60008"); pos != secure_string::npos) {
			error = "2FA";
			return false;
		}

		//Other errors
		if (secure_string message = getStringKey(output, "message"); !message.empty()) {
			error = message;
			return false;
		}

		//Success!
		if (secure_string token = getStringKey(output, "token"); !token.empty()) {
			error = token;
			return true;
		}

		//Unknown error
		error = "Unknown error";
		return false;
	}
	catch (std::exception& e) {
		g_logger.error(sf() << "Failed changePassword : " << e.what());
		error = e.what();
		return false;
	}
}

//Credit : https://guidedhacking.com/threads/how-to-pass-multiple-arguments-with-createremotethread-to-injected-dll.15373/

uintptr_t GetModuleBaseAddress(DWORD procId, const char* modName)
{
	uintptr_t modBaseAddr = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry))
		{
			do
			{
				if (!lstrcmpW(modEntry.szModule, s2ws(modName).c_str()))
				{
					modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap);
	return modBaseAddr;
}

//iPower's function
uintptr_t GetProcAddressEx(HANDLE hProcess, DWORD pid, const char* module, const char* function)
{
	if (!module || !function || !pid || !hProcess)
		return 0;

	uintptr_t moduleBase = GetModuleBaseAddress(pid, module); //toolhelp32snapshot method

	if (!moduleBase)
		return 0;

	IMAGE_DOS_HEADER Image_Dos_Header = { 0 };

	if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(moduleBase), &Image_Dos_Header, sizeof(IMAGE_DOS_HEADER), nullptr))
		return 0;

	if (Image_Dos_Header.e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	IMAGE_NT_HEADERS Image_Nt_Headers = { 0 };

	if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(moduleBase + Image_Dos_Header.e_lfanew), &Image_Nt_Headers, sizeof(IMAGE_NT_HEADERS), nullptr))
		return 0;

	if (Image_Nt_Headers.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	IMAGE_EXPORT_DIRECTORY Image_Export_Directory = { 0 };
	uintptr_t img_exp_dir_rva = 0;

	if (!(img_exp_dir_rva = Image_Nt_Headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress))
		return 0;

	if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(moduleBase + img_exp_dir_rva), &Image_Export_Directory, sizeof(IMAGE_EXPORT_DIRECTORY), nullptr))
		return 0;

	uintptr_t EAT = moduleBase + Image_Export_Directory.AddressOfFunctions;
	uintptr_t ENT = moduleBase + Image_Export_Directory.AddressOfNames;
	uintptr_t EOT = moduleBase + Image_Export_Directory.AddressOfNameOrdinals;

	WORD ordinal = 0;
	SIZE_T len_buf = strlen(function) + 1;
	char* temp_buf = new char[len_buf];

	for (size_t i = 0; i < Image_Export_Directory.NumberOfNames; i++)
	{
		uintptr_t tempRvaString = 0;

		if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(ENT + (i * sizeof(uintptr_t))), &tempRvaString, sizeof(uintptr_t), nullptr))
			return 0;

		if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(moduleBase + tempRvaString), temp_buf, len_buf, nullptr))
			return 0;

		if (!_stricmp(function, temp_buf))
		{
			if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(EOT + (i * sizeof(WORD))), &ordinal, sizeof(WORD), nullptr))
				return 0;

			uintptr_t temp_rva_func = 0;

			if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(EAT + (ordinal * sizeof(uintptr_t))), &temp_rva_func, sizeof(uintptr_t), nullptr))
				return 0;

			delete[] temp_buf;
			return moduleBase + temp_rva_func;
		}
	}
	delete[] temp_buf;
	return 0;
}
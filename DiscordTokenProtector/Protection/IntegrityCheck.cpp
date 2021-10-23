#include "IntegrityCheck.h"
#include "FileCert.h"
#include "../Utils/Logger.h"
#include "../Utils/Utils.h"
#include "../Utils/CurlUtils.h"
#include "../Crypto/CryptoUtils.h"

bool IntegrityCheck::check(const std::string& discordDir) {
	m_issues.clear();
	m_progress = 0;
	setTotalFilesToCheck(discordDir);

	try {
		if (m_discordVersion.empty()) throw std::runtime_error("The Discord version is not set!");

		filehash mainFileHash;

		if (m_checkFilehash) {
			std::string filename;
			if (downloadDiscordHash(m_discordVersion, "main", filename, m_redownloadHashes))
				mainFileHash = loadHashDump(filename);
			else
				m_issues.push_back({ discordDir, "Unable to get hashes for this version of Discord!" });
		}

		if (m_checkExecutableSignature || m_checkScripts || m_checkFilehash) {
			const std::string modulesDir = discordDir + "\\modules";

			for (const auto& file : std::filesystem::recursive_directory_iterator(discordDir)) {
				if (isFileIgnored(file)) continue;

				//Ignore the hash check for modules, it's checked by checkModules
				bool isModule = file.path().u8string().substr(0, modulesDir.size()) == modulesDir;

				if (file.is_directory()) {
					if (!isModule && m_checkFilehash && !mainFileHash.empty()) {
						std::string relativePath = getRelativePath(discordDir, file.path().u8string());

						if (auto it = mainFileHash.find(relativePath); it == mainFileHash.end() &&
							!(m_allowBetterDiscord && relativePath == "resources\\app"))
							m_issues.push_back({ file.path().u8string(), "Unexpected directory! 0x1" });
					}
					m_progress++;
				}
				else if (file.is_regular_file()) {
					if (!isModule && m_checkFilehash && !mainFileHash.empty()) {
						std::string relativePath = getRelativePath(discordDir, file.path().u8string());

						auto it = mainFileHash.find(relativePath);
						if (it == mainFileHash.end()) {
							if (!m_allowBetterDiscord ||
								(relativePath != "resources\\app\\index.js" && relativePath != "resources\\app\\package.json"))
								m_issues.push_back({ file.path().u8string(), "Unexpected file! 0x1" });
						}
						else if (CryptoUtils::SimpleSHA256(getFileContent(file.path().u8string())) != it->second) {
							m_issues.push_back({ file.path().u8string(), "Invalid hash!" });
						}
					}
					
					if (m_checkExecutableSignature && file.path().extension().u8string() == ".exe" || file.path().extension().u8string() == ".dll") {
						if (!VerifyEmbeddedSignature(file.path().wstring().c_str())) {
							m_issues.push_back({ file.path().u8string(), "Invalid digital signature!" });
						}
					}

					if (m_checkScripts && file.path().extension().u8string() == ".js") {
						checkKnownSignatures(file.path().u8string());
					}

					m_progress++;
				}
			}
		}

		if (m_checkModules) {
			checkModules(discordDir);
		}

		if (m_checkResources) {
			checkResources(discordDir);
		}
	}
	catch (std::exception& e) {
		g_logger.error(sf() << "Failed to check integrity : " << e.what());
		m_issues.push_back({"EXCEPTION", e.what()});
	}

	return m_issues.empty();
}

void IntegrityCheck::printIssues() {
	g_logger.info(sf() << "Issues count : " << m_issues.size());
	for (const auto& [dir, issue] : m_issues) {
		g_logger.info(sf() << dir << " - " << issue);
	}
}

bool IntegrityCheck::checkSig(const std::string& data, const std::vector<std::string>& sigs) {
	for (const auto& sig : sigs)
		if (data.find(sig) != std::string::npos)
			return true;

	return false;
}

uint32_t IntegrityCheck::getFileDirCountInDir(const std::string& dir, std::function<bool(std::filesystem::directory_entry)> isIgnoredFn) {
	auto dirIter = std::filesystem::recursive_directory_iterator(dir);
	return std::count_if(std::filesystem::begin(dirIter), std::filesystem::end(dirIter),
		[&](const auto& file) {return (file.is_regular_file() || file.is_directory()) && !isIgnoredFn(file); });
}

std::string IntegrityCheck::getRelativePath(std::string discordDir, std::string absolutePath) {
	if (discordDir[discordDir.size() - 1] != '\\') discordDir.push_back('\\');

	return absolutePath.substr(discordDir.size());
}

void IntegrityCheck::checkModules(const std::string& discordDir) {
	const std::string modulesDir = discordDir + "\\modules";

	for (const auto& moduleDir : std::filesystem::directory_iterator(modulesDir)) {
		if (moduleDir.is_directory()) {
			const std::string modulePath = moduleDir.path().u8string();

			uint32_t subDirCount = 0;

			filehash moduleFileHash;

			if (m_checkFilehash) {
				std::string filename;
				if (downloadDiscordHash(m_discordVersion, moduleDir.path().filename().u8string(), filename, m_redownloadHashes)) {
					moduleFileHash = loadHashDump(filename);
				}
				else
					m_issues.push_back({ modulePath, "Unable to find hashes for this module!" });
			}

			for (const auto& moduleSubDir : std::filesystem::directory_iterator(moduleDir)) {
				const std::string moduleName = moduleSubDir.path().filename().u8string();

				//Check if the module dir contains the module name
				if (moduleSubDir.is_directory()) {
					if (moduleDir.path().filename().u8string().find(moduleName) == std::string::npos) {
						m_issues.push_back({ moduleSubDir.path().u8string(), "Unexpected directory! 0x2" });
					}
					else {
						//Check hashes
						if (m_checkFilehash && !moduleFileHash.empty()) {
							for (const auto& file : std::filesystem::recursive_directory_iterator(modulePath)) {
								if (isFileIgnored(file)) continue;

								if (file.is_directory()) {
									std::string relativePath = getRelativePath(modulePath, file.path().u8string());

									if (auto it = moduleFileHash.find(relativePath); it == moduleFileHash.end())
										m_issues.push_back({ file.path().u8string(), "Unexpected directory! 0x3" });

									m_progress++;
								}
								else if (file.is_regular_file()) {
									std::string relativePath = getRelativePath(modulePath, file.path().u8string());

									auto it = moduleFileHash.find(relativePath);
									if (it == moduleFileHash.end()) {
										m_issues.push_back({ file.path().u8string(), "Unexpected file! 0x2" });
									}
									else if (CryptoUtils::SimpleSHA256(getFileContent(file.path().u8string())) != it->second) {
										m_issues.push_back({ file.path().u8string(), "Invalid hash!" });
									}

									m_progress++;
								}
							}
						}

						//Check the index
						const std::string indexFile = moduleSubDir.path().u8string() + "\\index.js";

						std::string fileContent = getFileContent(indexFile);

						if (fileContent.empty()) {
							m_issues.push_back({ indexFile, "Unable to open the file. Nonexistent?" });
						}
						else {
							if (fileContent != std::string(sf() << "module.exports = require(\'./" << moduleName << ".node\');\n")) {
								
								checkKnownSignatures(indexFile, fileContent);

								//TODO find a way to check them?
								static const std::vector<std::string> irregularModules = {
									"discord_cloudsync",
									"discord_dispatch",
									"discord_hook",
									"discord_krisp",
									"discord_media",
									"discord_overlay2",
									"discord_rpc",
									"discord_spellcheck",
									"discord_utils",
									"discord_voice"
								};

								if (moduleName == "discord_desktop_core") {
									if (fileContent != "module.exports = require(\'./core.asar\');")
										m_issues.push_back({ indexFile, "Invalid core init script!" });
								}
								else if (std::find(irregularModules.begin(), irregularModules.end(), moduleName) == irregularModules.end()) {
									m_issues.push_back({ indexFile, "Invalid module init script!" });
								}
							}
						}
					}
				}
				else if (moduleSubDir.is_regular_file()) {
					m_issues.push_back({ moduleSubDir.path().u8string(), "Unexpected file! 0x3" });
				}

				if (subDirCount++ > 1) {
					m_issues.push_back({ moduleSubDir.path().u8string(), sf() << "Too many subdirectories"});
				}
			}
		}
		else if (moduleDir.is_regular_file()) {
			m_issues.push_back({ moduleDir.path().u8string(), "Unexpected file! 0x4" });
		}
	}
}

void IntegrityCheck::checkKnownSignatures(const std::string& filename, const std::string& data) {
	std::string fileContent;
	if (data.empty()) {
		fileContent = getFileContent(filename);

		if (fileContent.empty()) {
			m_issues.push_back({ filename, "Unable to open the file." });
			return;
		}
	}

	if (checkSig(data.empty() ? fileContent : data, Signatures::anarchyGrabber))
		m_issues.push_back({ filename, "AnarchyGrabber3 signature detected!" });
	if (checkSig(data.empty() ? fileContent : data, Signatures::basic))
		m_issues.push_back({ filename, "Suspicious signature detected!" });
}

void IntegrityCheck::checkResources(const std::string& discordDir) {
	std::vector<std::string> expectedFiles = {
		"app.asar",
		"build_info.json",
		"bootstrap\\manifest.json"
	};

	if (m_allowBetterDiscord) {
		expectedFiles.push_back("app\\index.js");
		expectedFiles.push_back("app\\package.json");
	}

	const std::string resourcesDir = discordDir + "\\resources";

	//Prepend the dir
	for (auto& f : expectedFiles) f = resourcesDir + "\\" + f;

	for (const auto& file : std::filesystem::recursive_directory_iterator(resourcesDir)) {
		if (file.is_directory()) {
			if (file.path().filename() != "bootstrap" && (!m_allowBetterDiscord || file.path().filename() != "app")) {
				m_issues.push_back({ file.path().u8string(), "Unexpected directory! 0x4" });
			}
			m_progress++;
		}
		else if (file.is_regular_file()) {
			if (std::find(expectedFiles.begin(), expectedFiles.end(), file.path().u8string()) == expectedFiles.end()) {
				m_issues.push_back({ file.path().u8string(), "Unexpected file! 0x5" });
			}
			else if (m_allowBetterDiscord) {
				auto doubleBackslash = [](const std::string& content) {
					std::string out;
					out.reserve(content.size());
					for (const char c : content) {
						if (c == '\\') out += "\\\\";
						else out.push_back(c);
					}

					return out;
				};

				//Check if index.js loads betterdiscord
				if (file.path().filename().u8string() == "index.js" && 
					getFileContent(file.path().u8string()) !=
						std::string(sf() << "require(\""
							<< doubleBackslash(ws2s(getAppDataPathW()))
							<< "\\\\BetterDiscord\\\\data\\\\betterdiscord.asar\");")) {
					m_issues.push_back({ file.path().u8string(), "Invalid BetterDiscord script!" });
				}

				if (file.path().filename().u8string() == "package.json" &&
					getFileContent(file.path().u8string()) != "{\"name\":\"betterdiscord\",\"main\":\"index.js\"}") {
					m_issues.push_back({ file.path().u8string(), "Invalid BetterDiscord package!" });
				}
			}

			m_progress++;
		}
	}
}

void IntegrityCheck::setTotalFilesToCheck(const std::string& discordDir) {
	m_progressTotal = 0;

	if (m_checkExecutableSignature || m_checkScripts || m_checkFilehash)
		m_progressTotal += getFileDirCountInDir(discordDir, isFileIgnored);
	if (m_checkModules && m_checkFilehash) {
		for (const auto& moduleDir : std::filesystem::directory_iterator(discordDir + "\\modules")) {
			if (moduleDir.is_directory()) {
				m_progressTotal += getFileDirCountInDir(moduleDir.path().u8string());
			}
		}
	}
	if (m_checkResources) {
		m_progressTotal += getFileDirCountInDir(discordDir + "\\resources");
	}
}

void IntegrityCheck::dumpHashFiles(const std::string& dir, const std::string& outFilename) {
	dumpHashFiles(hashFilesinDir(dir), outFilename);
}

void IntegrityCheck::dumpHashFiles(const std::vector<std::pair<std::string, std::string>>& hashes, const std::string& outFilename) {
	if (hashes.empty()) return;

	std::ofstream dumpfile(outFilename);
	if (dumpfile.is_open()) {
		for (const auto& [file, hash] : hashes) {
			dumpfile << file << ":" << hash << std::endl;
		}
		dumpfile.close();
	}
	else {
		g_logger.warning(sf() << "IntegrityCheck::dumpHashFiles : failed to open dumpfile " << outFilename);
	}
}

IntegrityCheck::filehash IntegrityCheck::loadHashDump(const std::string& dumpFilename) {
	filehash output;

	std::ifstream dumpfile(dumpFilename);
	if (dumpfile.is_open()) {
		for (std::string line; std::getline(dumpfile, line);) {
			auto pos = line.find(':');
			if (pos == std::string::npos) continue;

			output.insert_or_assign(line.substr(0, pos), line.substr(pos + 1));
		}
	}

	return output;
}

std::vector<std::pair<std::string, std::string>> IntegrityCheck::hashFilesinDir(
	const std::string& dir,
	std::function<bool(std::filesystem::directory_entry)> isIgnoredFn) {

	if (dir.empty()) return {};

	std::vector<std::pair<std::string, std::string>> output;

	for (const auto& file : std::filesystem::recursive_directory_iterator(dir)) {
		if (isIgnoredFn(file)) continue;

		std::string filePath = getRelativePath(dir, file.path().u8string());

		if (file.is_directory()) {
			output.push_back({ filePath, "0000000000000000000000000000000000000000000000000000000000000000"});
		}
		else if (file.is_regular_file()) {
			std::string fileContent = getFileContent(file.path().u8string());
			if (fileContent.empty())
				g_logger.warning(sf() << "IntegrityCheck::hashFilesinDir : failed to open " << file.path().u8string());
			else
				output.push_back({ filePath, CryptoUtils::SimpleSHA256(fileContent) });
		}
	}

	return output;
}

bool IntegrityCheck::downloadDiscordHash(const std::string& version, const std::string& moduleName, std::string& outFilename, bool overWrite) {
	outFilename.clear();
	outFilename = "cache\\" + version + "_" + moduleName + ".hash";

	if (!overWrite && std::filesystem::exists(outFilename)) return true;

	secure_string output;

	//TODO sanitize version?
	try {
		cURL_get(HASH_URL + version + "/" + moduleName + ".hash", nullptr, output);

		//TODO better check ?
		if (output == "404: Not Found") throw std::runtime_error("version not hashed");

		std::ofstream hashfile(outFilename, std::ios::binary);
		hashfile << output;
	}
	catch (std::exception& e) {
		g_logger.warning(sf() << "Failed to download discord hash : " << e.what());
		return false;
	}

	return true;
}

bool IntegrityCheck::isFileIgnored(std::filesystem::directory_entry file) {
	if (file.path().has_extension() &&
		std::find(IGNORED_EXT.begin(), IGNORED_EXT.end(), file.path().extension().u8string()) != IGNORED_EXT.end()) return true;

	//More condition?

	return false;
}

void IntegrityCheck::dumpCurrentDiscordHashes(const std::string& discordDir, const std::string& version) {
	const std::string modulesDir = discordDir + "\\modules";

	if (!std::filesystem::exists(version)) {
		std::filesystem::create_directory(version);
	}

	dumpHashFiles(hashFilesinDir(discordDir, [&modulesDir](std::filesystem::directory_entry file) {
		//Ignore ignored files & modules directory
		return isFileIgnored(file) || file.path().u8string().substr(0, modulesDir.size()) == modulesDir;
	}), version + "\\main.hash");

	for (const auto& file : std::filesystem::directory_iterator(modulesDir)) {
		if (file.is_directory()) {
			dumpHashFiles(hashFilesinDir(file.path().u8string()), version + "\\" + file.path().filename().u8string() + ".hash");
		}
	}
}
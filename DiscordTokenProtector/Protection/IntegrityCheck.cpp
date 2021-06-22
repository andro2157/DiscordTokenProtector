#include "IntegrityCheck.h"
#include "FileCert.h"
#include "../Utils/Logger.h"
#include "../Utils/Utils.h"
#include "../Crypto/CryptoUtils.h"

bool IntegrityCheck::check(const std::string& discordDir) {
	m_progress = 0;
	m_progressTotal = 0;

	try {
		if (m_checkFilehash && m_fileHash.empty()) {
			throw std::runtime_error("Tried to check file hashes without the hashes");
		}

		if (m_checkExecutableSignature || m_checkScripts || m_checkFilehash) {
			m_progressTotal += getFileDirCountInDir(discordDir);

			for (const auto& file : std::filesystem::recursive_directory_iterator(discordDir)) {
				if (file.is_directory()) {
					if (m_checkFilehash) {
						std::string relativePath = getRelativePath(discordDir, file.path().u8string());

						if (auto it = m_fileHash.find(relativePath); it == m_fileHash.end() &&
							!(m_allowBetterDiscord && relativePath == "resources\\app"))
							m_issues.push_back({ file.path().u8string(), "Unexpected directory!" });
					}
					m_progress++;
				}
				else if (file.is_regular_file()) {
					if (m_checkFilehash) {
						std::string relativePath = getRelativePath(discordDir, file.path().u8string());

						auto it = m_fileHash.find(relativePath);
						if (it == m_fileHash.end()) {
							if (!m_allowBetterDiscord ||
								(relativePath != "resources\\app\\index.js" && relativePath != "resources\\app\\package.json"))
								m_issues.push_back({ file.path().u8string(), "Unexpected file!" });
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

	return !m_issues.empty();
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

size_t IntegrityCheck::getFileDirCountInDir(const std::string& dir) {
	auto dirIter = std::filesystem::recursive_directory_iterator(dir);
	return std::count_if(std::filesystem::begin(dirIter), std::filesystem::end(dirIter),
		[](const auto& file) {return file.is_regular_file() || file.is_directory(); });
}

std::string IntegrityCheck::getRelativePath(std::string discordDir, std::string absolutePath) {
	if (discordDir[discordDir.size() - 1] != '\\') discordDir.push_back('\\');

	return absolutePath.substr(discordDir.size());
}

void IntegrityCheck::checkModules(const std::string& discordDir) {
	const std::string modulesDir = discordDir + "\\modules";
	m_progressTotal += getFileDirCountInDir(modulesDir);

	for (const auto& moduleDir : std::filesystem::directory_iterator(modulesDir)) {
		if (moduleDir.is_directory()) {
			size_t subDirCount = 0;

			for (const auto& moduleSubDir : std::filesystem::directory_iterator(moduleDir)) {
				const std::string moduleName = moduleSubDir.path().filename().u8string();

				//Check if the module dir contains the module name
				if (moduleSubDir.is_directory()) {
					if (moduleDir.path().filename().u8string().find(moduleName) == std::string::npos) {
						m_issues.push_back({ moduleSubDir.path().u8string(), "Unexpected directory!" });
					}
					else {
						//Check the index
						const std::string indexFile = moduleSubDir.path().u8string() + "\\index.js";

						std::string fileContent = getFileContent(indexFile);

						if (fileContent.empty()) {
							m_issues.push_back({ indexFile, "Unable to open the file. Nonexistent?" });
						}
						else {
							if (fileContent != std::string(sf() << "module.exports = require(\'./" << moduleName << ".node\');\n")) {
								if (!m_checkScripts) {
									checkKnownSignatures(indexFile, fileContent);
								}

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
					m_issues.push_back({ moduleSubDir.path().u8string(), "Unexpected file!" });
				}

				subDirCount++;
			}

			m_progress++;
		}
		else if (moduleDir.is_regular_file()) {
			m_issues.push_back({ moduleDir.path().u8string(), "Unexpected file!" });
			m_progress++;
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

	const std::string ressourcesDir = discordDir + "\\resources";

	//Prepend the dir
	for (auto& f : expectedFiles) f = ressourcesDir + "\\" + f;

	m_progressTotal += getFileDirCountInDir(ressourcesDir);

	for (const auto& file : std::filesystem::recursive_directory_iterator(ressourcesDir)) {
		if (file.is_directory()) {
			if (file.path().filename() != "bootstrap" && (!m_allowBetterDiscord || file.path().filename() != "app")) {
				m_issues.push_back({ file.path().u8string(), "Unexpected directory!" });
			}
			m_progress++;
		}
		else if (file.is_regular_file()) {
			if (std::find(expectedFiles.begin(), expectedFiles.end(), file.path().u8string()) == expectedFiles.end()) {
				m_issues.push_back({ file.path().u8string(), "Unexpected file!" });
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

void IntegrityCheck::dumpHashFiles(const std::string& dir, const std::string& outFilename) {
	auto hashes = hashFilesinDir(dir);
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

std::vector<std::pair<std::string, std::string>> IntegrityCheck::hashFilesinDir(const std::string& dir) {
	if (dir.empty()) return {};

	std::vector<std::pair<std::string, std::string>> output;

	for (const auto& file : std::filesystem::recursive_directory_iterator(dir)) {
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
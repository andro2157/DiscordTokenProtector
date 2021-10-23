#pragma once
#include "../Includes.h"

namespace Signatures {
	inline const std::vector<std::string> anarchyGrabber = {
		"anarchyHook",
		"4n4rchy",
		"\\\\inject",
		"process.env.hook",
		"\"lo\" + \"gi\" + \"n\";"
	};

	inline const std::vector<std::string> basic = {
		"https://discord.com/api/webhooks/",
		"/users/@me/billing/payments",
		"/users/@me/entitlements/gifts"
	};
}

constexpr auto HASH_URL = "https://raw.githubusercontent.com/andro2157/DiscordTokenProtector/master/DiscordHash/";

const inline std::vector<std::string> IGNORED_EXT = {".log", ".tmp"};

class IntegrityCheck {
public:
	//dir, issue
	using issues = std::vector<std::pair<std::string, std::string>>;
	//dir, hash
	using filehash = std::map<std::string, std::string>;

	IntegrityCheck() {
		if (!std::filesystem::exists("cache")) std::filesystem::create_directory("cache");
	}

	bool check(const std::string& discordDir);

	issues getIssues() const { return m_issues; }

	void setCheckExecutableSig(const bool check) { m_checkExecutableSignature = check; }
	bool isCheckingExecutableSig() const { return m_checkExecutableSignature; }
	void setCheckModule(const bool check) { m_checkModules = check; }
	bool isCheckingModule() const { return m_checkModules; }
	void setCheckScripts(const bool check) { m_checkScripts = check; }
	bool isCheckingScripts() const { return m_checkScripts; }
	void setCheckResources(const bool check) { m_checkResources = check; }
	bool isCheckingResources() const { return m_checkResources; }
	void setCheckHash(const bool check) { m_checkFilehash = check; }
	bool isCheckingHash() const { return m_checkFilehash; }

	void setAllowBetterDiscord(const bool allow) { m_allowBetterDiscord = allow; }
	bool isAllowingBetterDiscord() const { return m_allowBetterDiscord; }

	void setRedownloadHashes(const bool redownload) { m_redownloadHashes = redownload; }
	bool isRedownloadingHashes() const { return m_redownloadHashes; }

	void setDiscordVersion(const std::string& version) { m_discordVersion = version; }
	std::string getDiscordVersion() const { return m_discordVersion; }

	uint32_t getProgress() const { return m_progress; }
	uint32_t getProgressTotal() const { return m_progressTotal; }

	void printIssues();

	//Use this to dump the hashes of your current installation!
	static void dumpCurrentDiscordHashes(const std::string& discordDir, const std::string& version);

	static void dumpHashFiles(const std::string& dir, const std::string& outFilename);
	static void dumpHashFiles(const std::vector<std::pair<std::string, std::string>>& hashes, const std::string& outFilename);

	static filehash loadHashDump(const std::string& dumpFilename);
	static std::vector<std::pair<std::string, std::string>> hashFilesinDir(const std::string& dir,
		std::function<bool(std::filesystem::directory_entry)> isIgnoredFn = isFileIgnored);
	//For the non-modules hashes, moduleName = "main"
	static bool downloadDiscordHash(const std::string& version, const std::string& moduleName, std::string& outFilename, bool overWrite = false);

private:
	static bool checkSig(const std::string& data, const std::vector<std::string>& sigs);	
	static uint32_t getFileDirCountInDir(const std::string& dir,
		std::function<bool(std::filesystem::directory_entry)> isIgnoredFn = [](std::filesystem::directory_entry file) {return false; });
	static std::string getRelativePath(std::string discordDir, std::string absolutePath);
	static bool isFileIgnored(std::filesystem::directory_entry file);

	void checkModules(const std::string& discordDir);
	void checkKnownSignatures(const std::string& filename, const std::string& data = "");
	void checkResources(const std::string& discordDir);

	void setTotalFilesToCheck(const std::string& discordDir);

	issues m_issues;

	bool m_checkExecutableSignature = false;
	bool m_checkModules = false;
	bool m_checkScripts = false;
	bool m_checkResources = false;
	bool m_checkFilehash = false;

	bool m_allowBetterDiscord = false;

	bool m_redownloadHashes = false;

	std::atomic_uint32_t m_progress = 0;
	std::atomic_uint32_t m_progressTotal = 0;

	std::string m_discordVersion;
};
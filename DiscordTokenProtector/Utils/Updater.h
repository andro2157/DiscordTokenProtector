#pragma once
#include "../Includes.h"
#include "CurlUtils.h"

namespace Updater {
	static const std::string UPDATE_ERROR = "UPDATE_ERROR";

	std::string getLastestVersion() {
		secure_string out;
		try {
			cURL_get("https://raw.githubusercontent.com/andro2157/DiscordTokenProtector/master/Update/version.txt", nullptr, out);
		}
		catch (std::exception& e) {
			return UPDATE_ERROR;
		}
		return std::string(out);
	}
	std::string getChangeLogs() {
		secure_string out;
		try {
			cURL_get("https://raw.githubusercontent.com/andro2157/DiscordTokenProtector/master/Update/changelog.txt", nullptr, out);
		}
		catch (std::exception& e) {
			return UPDATE_ERROR;
		}
		return std::string(out);
	}
}

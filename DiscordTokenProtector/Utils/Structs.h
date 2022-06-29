#pragma once
#include <iostream>

//No need to store more info
struct DiscordUserInfo {
	std::string fullUsername = "";//username#discriminator
	std::string username = "";
	std::string discriminator = "";
	std::string id = "";
	bool mfa = false;
};
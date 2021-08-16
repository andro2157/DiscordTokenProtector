#pragma once
#include "../Includes.h"
#include <imgui.h>

namespace Colors {
	inline const ImVec4 getColorFromHex(const uint32_t hex) {
		return ImGui::ColorConvertU32ToFloat4(_byteswap_ulong(hex));
	}

	//https://discord.com/branding
	inline const ImVec4 Blurple = getColorFromHex(0x7289DAFF);
	inline const ImVec4 White = getColorFromHex(0xFFFFFFFF);
	inline const ImVec4 GrayPurple = getColorFromHex(0x99AAB5FF);
	inline const ImVec4 DarkButNotBlack = getColorFromHex(0x2C2F33FF);
	inline const ImVec4 NearlyBlack = getColorFromHex(0x23272AFF);
	inline const ImVec4 Black = getColorFromHex(0x000000FF);

	//From the app
	inline const ImVec4 Red = getColorFromHex(0xF04747FF);
	inline const ImVec4 Green = getColorFromHex(0x43B581FF);
	inline const ImVec4 LinkBlue = getColorFromHex(0x2494F4FF);

	inline const ImVec4 HoverBlack = getColorFromHex(0x34373CFF);
	inline const ImVec4 ActiveBlack = getColorFromHex(0x37393FFF);

	inline const ImVec4 BorderBlack = getColorFromHex(0x282A2FFF);

	inline const ImVec4 BlurpleHover = getColorFromHex(0x677BC4FF);
	inline const ImVec4 BlurpleActive = getColorFromHex(0x5B6EAEFF);

	inline const ImVec4 ScrollBar = getColorFromHex(0x202225FF);

	inline const ImVec4 Transparent = getColorFromHex(0x00000000);

	inline const ImVec4 Separator = getColorFromHex(0x42454AFF);
}
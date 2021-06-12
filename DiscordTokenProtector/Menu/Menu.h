#pragma once
#include "../Includes.h"

//Mostly from https://github.com/ocornut/imgui/blob/master/examples/example_glfw_opengl3/main.cpp
#define GLFW_EXPOSE_NATIVE_WIN32

#include "../Lib/imgui/imgui.h"
#include "../Lib/imgui/imgui_impl_glfw.h"
#include "../Lib/imgui/imgui_impl_opengl3.h"

#include "../Lib/imgui/GL/gl3w.h"
#include "../Lib/imgui/GLFW/glfw3.h"
#include "../Lib/imgui/GLFW/glfw3native.h"

namespace Menu {
	extern ImFont* largeFont;
	extern ImFont* smallFont;
	extern ImFont* monospaceFont;

	static void glfw_error_callback(int error, const char* description);
	void SetupWindow();
	void SetupMenu();
	void InvalidHWID();
	void StartupPassword();
	void MainMenu();
	void HomeTab();
	void AccountTab();
	void SettingsTab();
}
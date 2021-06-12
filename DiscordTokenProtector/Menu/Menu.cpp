#include "Menu.h"
#include "FrameRateLimiter.h"
#include "Colors.h"
#include "ImGuiAddon.h"

#include "../Context.h"

#include "shellapi.h"
#include "../resource.h"

FrameRateLimiter g_fpslimit(FPS_MAX);

namespace Menu {
	ImFont* largeFont = nullptr;
	ImFont* smallFont = nullptr;
	ImFont* monospaceFont = nullptr;

	WNDPROC originalWndProc = nullptr;
	HWND mainHwnd = NULL;
	HMENU trayMenu = NULL;

	bool running = true;

	LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

	constexpr auto WM_DTPMSG = WM_USER + 1;
	constexpr auto TRAY_ID_QUIT = 1337;

	static void glfw_error_callback(int error, const char* description) {
		g_logger.error(sf() << "Glfw Error " << error << ": " << description);
	}

	void TrayBarNotify(std::string title, std::string msg, int msTimeout) {
		NOTIFYICONDATAA nid = { sizeof(nid) };
		nid.uFlags = NIF_INFO;
		nid.hWnd = mainHwnd;
		strcpy_s(nid.szInfo, msg.c_str());
		strcpy_s(nid.szInfoTitle, title.c_str());
		nid.uTimeout = msTimeout;
		nid.dwInfoFlags = NIIF_INFO;
		Shell_NotifyIconA(NIM_MODIFY, &nid);
	}

	void SetupWindow() {
		glfwSetErrorCallback(glfw_error_callback);
		if (!glfwInit()) {
			FATALERROR("Failed to init GLFW!");
		}

		// GL 3.0 + GLSL 130
		const char* glsl_version = "#version 130";
		glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
		glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

		GLFWwindow* window = glfwCreateWindow(500, 375, "Discord Token Protector " VER, NULL, NULL);
		if (window == NULL)
			return;
		glfwMakeContextCurrent(window);
		glfwSwapInterval(1); // Enable vsync
		glfwSetWindowSizeLimits(window, 600, 375, 600, 375);

		bool err = gl3wInit() != 0;
		if (err) {
			FATALERROR("Failed to initialize OpenGL loader!");
		}

		mainHwnd = glfwGetWin32Window(window);
		originalWndProc = reinterpret_cast<WNDPROC>(GetWindowLongPtr(mainHwnd, GWL_WNDPROC));
		SetWindowLongPtr(mainHwnd, GWL_WNDPROC, reinterpret_cast<LONG>(WndProc));

		//Window icon
		HICON hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_ICON1));
		SendMessage(mainHwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
		SendMessage(mainHwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
		//

		//Trayicon
		hIcon = (HICON)LoadImage(GetModuleHandle(NULL),
			MAKEINTRESOURCE(IDI_ICON1),
			IMAGE_ICON,
			GetSystemMetrics(SM_CXSMICON),
			GetSystemMetrics(SM_CYSMICON),
			LR_DEFAULTCOLOR);

		NOTIFYICONDATAA nid = { sizeof(nid) };
		nid.hWnd = mainHwnd;
		nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_SHOWTIP;
		nid.hIcon = hIcon;
		nid.uCallbackMessage = WM_DTPMSG;
		nid.uVersion = NOTIFYICON_VERSION_4;
		
		const char* infoTitle = "Discord Token Protector";
		strcpy_s(nid.szInfoTitle, infoTitle);

		Shell_NotifyIconA(NIM_ADD, &nid);

		if (trayMenu = CreatePopupMenu(); trayMenu == NULL) { FATALERROR("Failed CreatePopupMenu"); }
		if (!AppendMenu(trayMenu, MF_STRING, TRAY_ID_QUIT, TEXT("Quit"))) { FATALERROR("Failed AppendMenu"); }

		//

		// Setup Dear ImGui context
		IMGUI_CHECKVERSION();
		ImGui::CreateContext();
		ImGuiIO& io = ImGui::GetIO(); (void)io;
		io.IniFilename = NULL;

		ImGui::StyleColorDiscord();
		ImGuiStyle* style = &ImGui::GetStyle();
		style->WindowRounding = 0.f;
		style->FrameRounding = 4.f;

		// Setup Platform/Renderer bindings
		ImGui_ImplGlfw_InitForOpenGL(window, true);
		ImGui_ImplOpenGL3_Init(glsl_version);

		// Load Fonts
		io.FontDefault = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\verdana.ttf", 18.f);
		IM_ASSERT(io.FontDefault != NULL);
		largeFont = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\verdana.ttf", 28.f);
		IM_ASSERT(largeFont != NULL);
		smallFont = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\verdana.ttf", 13.f);
		IM_ASSERT(smallFont != NULL);
		monospaceFont = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\consola.ttf", 18.f);
		IM_ASSERT(monospaceFont != NULL);

		ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

		std::once_flag trayMiniNotify;

		// Main loop
		while (running) {
			glfwPollEvents();

			if (glfwWindowShouldClose(window)) {
				ShowWindow(mainHwnd, SW_HIDE);
				glfwSetWindowShouldClose(window, FALSE);

				std::call_once(trayMiniNotify, TrayBarNotify, "Discord Token Protector", "Minimized in the tray bar", 2000);
			}

			if (!IsWindowVisible(mainHwnd)) {
				std::this_thread::sleep_for(std::chrono::milliseconds(10));
				continue;
			}

			// Start the Dear ImGui frame
			ImGui_ImplOpenGL3_NewFrame();
			ImGui_ImplGlfw_NewFrame();
			ImGui::NewFrame();

			if (GetActiveWindow() != mainHwnd)
				g_fpslimit.setFrameRate(FPS_IDLE_MAX);//Limit fps if the window is not on the foreground
			else
				g_fpslimit.setFrameRate(FPS_MAX);

			g_fpslimit.frameStart();

			if (ImGui::Begin("##MainWindow", nullptr, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoTitleBar)) {
				ImGui::SetWindowPos(ImVec2(0, 0));

				int window_width = 0, window_height = 0;
				glfwGetWindowSize(window, &window_width, &window_height);
				ImGui::SetWindowSize(ImVec2(static_cast<float>(window_width), static_cast<float>(window_height)));

				ImGui::Indent(16.f);

				ImGui::PushFont(largeFont);
				ImGui::Text("Discord Token Protector");
				ImGui::PopFont();

				ImGui::SameLine();

				ImGui::PushFont(smallFont);
				ImGui::Text("by Andro24");
				ImGui::PopFont();

				ImGui::Unindent();

				ImGui::NewLine();

				if (g_context.state == State::TokenSecure)
					MainMenu();
				else if (g_context.state == State::RequirePassword)
					StartupPassword();
				else if (g_context.state == State::InvalidHWID)
					InvalidHWID();
				else
					SetupMenu();

				ImGui::End();
			}

			// Rendering
			ImGui::Render();
			int display_w, display_h;
			glfwGetFramebufferSize(window, &display_w, &display_h);
			glViewport(0, 0, display_w, display_h);
			glClearColor(clear_color.x, clear_color.y, clear_color.z, clear_color.w);
			glClear(GL_COLOR_BUFFER_BIT);
			ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

			glfwSwapBuffers(window);

			g_fpslimit.frameEnd();
		}

		//traymsgThread.join();

		//Remove tray icon
		Shell_NotifyIconA(NIM_DELETE, &nid);
		DestroyWindow(nid.hWnd);

		// Cleanup
		ImGui_ImplOpenGL3_Shutdown();
		ImGui_ImplGlfw_Shutdown();
		ImGui::DestroyContext();

		glfwDestroyWindow(window);
		glfwTerminate();
	}

	void InvalidHWID() {
		ImGui::Indent(32.f);
		ImGui::PushFont(largeFont);
		ImGui::Text("Error");
		ImGui::PopFont();
		ImGui::Unindent();

		ImGui::NewLine();

		ImGui::TextWrapped("We\'re sorry but we\'re unable to decrypt the container.");
		ImGui::TextWrapped("It seems like the HWID has changed.");
		ImGui::TextWrapped("We\'ll need to reset the container to get the token back.");

		ImGui::NewLine();

		if (ImGui::Button("Okay", ImVec2(ImGui::GetWindowWidth() - 30, 30))) {
			g_secureKV->reopenFile(true);
			g_context.state = State::NoToken;
		}
	}

	void StartupPassword() {
		ImGui::Indent(32.f);
		ImGui::PushFont(largeFont);
		ImGui::Text("Password");
		ImGui::PopFont();
		ImGui::Unindent();

		ImGui::NewLine();

		ImGui::TextWrapped("Please enter the password of the container:");

		static char passwordInput[256];//TODO FIX the password is still in the memory after the SecureZeroMemory.
		bool enterUnlock = ImGui::InputText("##Password", passwordInput, 256, ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue);

		ImGui::NewLine();

		static std::future<void> asyncUnlock;
		static bool unlocking = false;

		if (unlocking) {
			ImGui::PushItemFlag(ImGuiItemFlags_Disabled, true);
			ImGui::Button("Unlocking...", ImVec2(ImGui::GetWindowWidth() - 30, 30));
			ImGui::PopItemFlag();
			ImGui::LinearIndeterminateBar("progressindicator", ImVec2(ImGui::GetWindowWidth() - 22, 10));
		}
		else {
			if (ImGui::Button("Unlock", ImVec2(ImGui::GetWindowWidth() - 30, 30)) || enterUnlock) {
				asyncUnlock = std::async(std::launch::async, [](secure_string password) {
					uint32_t iterations_key = g_config->read<uint32_t>("iterations_key");
					uint32_t iterations_iv = g_config->read<uint32_t>("iterations_iv");
					//TODO add sanitary check of iterations

					g_context.kd.type = g_context.encryptionType_cache;
					g_context.kd.key = Crypto::derivateKey(password, CryptoPP::AES::MAX_KEYLENGTH, iterations_key);
					g_context.kd.iv = Crypto::derivateKey(password, CryptoPP::AES::BLOCKSIZE * 16, iterations_iv);

					secure_string token = g_secureKV->read("token", g_context.kd);
					if (token.empty()) {
						g_context.kd.reset();
						token.clear();

						//TODO proper ImGui thing
						MessageBoxA(NULL,
							(g_context.kd.type == EncryptionType::Password)
							? "Invalid password" : "Invalid password or HWID",
							"Discord Token Protector", MB_ICONSTOP | MB_OK);
					}
					else if (Discord::getUserInfo(token).empty()) {
						MessageBoxA(NULL, "The token is invalid. Please check the log for more info.", "Discord Token Protector", MB_ICONSTOP | MB_OK);
						g_secureKV->reopenFile(false);//Reset
						ExitProcess(0);
					}
					else {
						g_context.state = State::TokenSecure;

						//Clean the local storage and session storage (just in case)
						g_context.remover_LocalStorage.Remove();
						g_context.remover_SessionStorage.Remove();
						g_context.remover_canary_LocalStorage.Remove();
						g_context.remover_canary_SessionStorage.Remove();
					}

					if (g_config->read<bool>("auto_start"))
						g_context.startProtection();
					unlocking = false;
				}, secure_string(passwordInput));
				SecureZeroMemory(passwordInput, 256);

				unlocking = true;
			}
		}
	}

	//TODO split?
	//TODO reset? (for the back button)
	void SetupMenu() {
		ImGui::Indent(32.f);
		ImGui::PushFont(largeFont);
		ImGui::Text("Setup");
		ImGui::PopFont();
		ImGui::Unindent();

		ImGui::NewLine();

		static bool firstMessage = true;
		if (firstMessage) {
			ImGui::TextWrapped("Hello, thank you for installing Discord Token Protector (DTP).");
			ImGui::TextWrapped("We\'ll make sure that your Discord token is securely stored.");
			ImGui::TextWrapped("But keep in mind that this is NOT a perfect solution, still be careful of what "
				"you\'re downloading online!");
			ImGui::NewLine();

			ImGui::TextWrapped("By using DTP, your client side user settings will be wiped (Discord shortcuts, "
				"selected output device, etc). But server side ones aren\'t (Privacy settings, theme, users descriptions, etc)");

			ImGui::NewLine();

			ImGui::TextTooltip("(?) Note for Canary users.", "Discord Canary doesn\'t seem to support handoff connection. Therefore, "
				"Discord Token Protector cannot work with it!"
				/*"Discord Token Protector supports Canary build but it yet doesn\'t support "
				"multiple accounts. Therefore, it will only select one account."*/);

			if (ImGui::Button("I\'m ready to use DTP", ImVec2(ImGui::GetWindowWidth() - 30, 30))) {
				firstMessage = false;
			}
			return;
		}

		static Timer updateTimer;

		if (g_context.state == State::NoToken) {
			static int step = 0;
			if (updateTimer.getElapsed<std::chrono::milliseconds>() > 1000) {
				if (step == 0) {
					if (g_discord->isDiscordRunning() != DiscordType::None)
						step = 1;
				} else if (step == 1) {
					if (g_discord->isDiscordRunning() == DiscordType::None)
						step = 2;
				}
				else if (step == 2) {
					g_context.initTokenState();
				}
			}

			ImGui::TextWrapped("Hey! We\'re unable to detect your Discord token on this computer!\n"
				"Please follow these steps:");
			ImGui::NewLine();
			ImGui::TextColored(step > 0 ? Colors::Green : Colors::GrayPurple, "* Launch the Discord app and connect to your account.");
			ImGui::TextColored(step > 1 ? Colors::Green : Colors::GrayPurple, "* Quit the Discord app.");
			ImGui::TextColored(Colors::GrayPurple, "* Wait for us to detect your token.");
			ImGui::NewLine();
			if (step > 1)
				ImGui::TextWrapped("If the detection doesn\'t work, please make a ticket on GitHub.");
		}
		else if (g_context.state == State::DiscoveredToken) {
			static std::string info;
			static std::future<void> getInfoAsync = std::async(std::launch::async, []() {
				info = Discord::getUserInfo(Discord::getStoredToken(true));
			});

			ImGui::TextWrapped("We found this account:");
			ImGui::NewLine();

			ImGui::Text(info.empty() ? "Getting user info..." : info.c_str());

			ImGui::NewLine();

			ImGui::TextWrapped("This account\'s token will be secured, and you\'ll be automatically "
				"logged into this account when launching Discord.");

			ImGui::NewLine();

			if (!info.empty()) {
				if (ImGui::Button("It\'s correct!", ImVec2(ImGui::GetWindowWidth() - 30, 30))) {
					g_context.state = State::MakeNewPassword;
				}
			}
		}
		else if (g_context.state == State::MakeNewPassword ||
			g_context.encryptionType_cache == EncryptionType::Unknown) {
			static bool done = false;
			static int selectedEncryptionMode = 1;

			static char passwordInput[256];
			static char password2Input[256];

			static float hashTime = 0.5f;

			auto reset = [&]() {
				SecureZeroMemory(passwordInput, 256);
				SecureZeroMemory(password2Input, 256);
			};

			ImGui::TextWrapped("Let\'s now setup the secure container that will store your token!\n"
				"Please chose the mode:");
			ImGui::Combo("Encryption Mode", &selectedEncryptionMode, "Password-less (HWID)\0Password\0Password + HWID\0\0");
			if (selectedEncryptionMode == 0) {
				ImGui::TextColored(Colors::Red, "Warning!");
				ImGui::TextWrapped("This mode doesn\'t require a password, but the secure container can be easily "
					"decrypted by a program running on this computer using your user account. "
					"For example : a malware, someone accessing your pc, etc");
				reset();
			}
			else if (selectedEncryptionMode > 0) {
				ImGui::InputText("Password", passwordInput, 256, ImGuiInputTextFlags_Password);
				ImGui::InputText("Confirm Password", password2Input, 256, ImGuiInputTextFlags_Password);
				ImGui::SliderFloat("Hash Time", &hashTime, 0.1f, 3.0f, "%.2fs");
				ImGui::SameLine();
				ImGui::TextTooltip("(?)", "This corresponds to the time taken to hash your password. "
					"The longer it is, the more time it will take to unlock the container. But it\'ll "
					"also make it more secure against bruteforcing.");
				if (selectedEncryptionMode == 1)
					ImGui::NewLine();
			}
			if (selectedEncryptionMode == 0 || selectedEncryptionMode == 2) {
				ImGui::TextWrapped("Please also keep in mind that, with the HWID one, "
					"the container content will be lost if you change your "
					"Windows user account, if you reinstall Windows, or if you change your computer.");
			}

			static std::future<void> asyncStoreToken;

			if (done) {
				ImGui::PushItemFlag(ImGuiItemFlags_Disabled, true);
				ImGui::Button("Encrypting...", ImVec2(ImGui::GetWindowWidth() - 30, 30));
				ImGui::PopItemFlag();
				ImGui::LinearIndeterminateBar("progressindicator", ImVec2(ImGui::GetWindowWidth() - 22, 10));
			}
			else {
				if (ImGui::Button("Continue", ImVec2(ImGui::GetWindowWidth() - 30, 30))) {
					if (selectedEncryptionMode != 0 && strcmp(passwordInput, password2Input) != 0) {
						//TODO proper thing in ImGui
						MessageBoxA(NULL, "Passwords aren\'t identical.", "Discord Token Protector", MB_ICONWARNING | MB_OK);
					}
					else if (selectedEncryptionMode != 0 && strlen(passwordInput) < 6) {//TODO change?
						MessageBoxA(NULL, "The password must have at least 6 characters.", "Discord Token Protector", MB_ICONWARNING | MB_OK);
					}
					else {
						asyncStoreToken = std::async(std::launch::async, [](secure_string password) {
							if (selectedEncryptionMode == 0) {
								g_context.kd = HWID_kd;
							}
							else {
								if (selectedEncryptionMode == 1)
									g_context.kd.type = EncryptionType::Password;
								if (selectedEncryptionMode == 2)
									g_context.kd.type = EncryptionType::HWIDAndPassword;

								float singleHashTime = hashTime / 2;
								uint32_t iterations_key = 0;
								uint32_t iterations_iv = 0;

								g_context.kd.key = Crypto::derivateKey(password, CryptoPP::AES::MAX_KEYLENGTH, iterations_key, singleHashTime);
								g_context.kd.iv = Crypto::derivateKey(password, CryptoPP::AES::BLOCKSIZE * 16, iterations_iv, singleHashTime);

								//TODO add check if iterations == 0, (this shouldn't happen)

								g_config->write("iterations_key", iterations_key);
								g_config->write("iterations_iv", iterations_iv);
							}

							g_secureKV->write("token", Discord::getStoredToken(false), g_context.kd);

							//Clean the local storage and session storage
							g_context.remover_canary_LocalStorage.Remove();
							g_context.remover_canary_SessionStorage.Remove();

							//Finished setup
							g_context.state = State::TokenSecure;
							g_context.startProtection();
							done = false;
						}, secure_string(passwordInput));
						done = true;
					}
					reset();
				}
			}
		}
		ImGui::Unindent();
	}

	void MainMenu() {
		ImGui::Indent(4.f);

		if (ImGui::BeginTabBar("##Tabs")) {
			if (ImGui::BeginTabItem("Home")) {
				HomeTab();
				ImGui::EndTabItem();
			}
			if (ImGui::BeginTabItem("Account")) {
				AccountTab();
				ImGui::EndTabItem();
			}
			if (ImGui::BeginTabItem("Settings")) {
				SettingsTab();
				ImGui::EndTabItem();
			}
			if (ImGui::BeginTabItem("About")) {
				ImGui::Text("Version : " VER);
				ImGui::Text("Made by Andro24");
				ImGui::Text("Github : @andro2157");
				ImGui::NewLine();
				ImGui::Text("Original icon made by Pixel perfect from www.flaticon.com");
				ImGui::EndTabItem();
			}
		}

		ImGui::Unindent();
	}

	void HomeTab() {
		if (ImGui::BeginChild("HomeTab")) {
			ImGui::PushFont(largeFont);
			if (g_context.m_running)
				ImGui::TextColored(Colors::Green, "Protected!");
			else
				ImGui::TextColored(Colors::Red, "NOT Protected!");
			ImGui::PopFont();

			ImGui::NewLine();

			if (g_context.m_running)
				ImGui::Text("Current status : %s", 
					(g_context.m_protectionState == ProtectionStates::Idle) ? "Waiting for Discord..." :
					(g_context.m_protectionState == ProtectionStates::Injecting) ? "Injecting payload..." : 
					(g_context.m_protectionState == ProtectionStates::Connected) ? "Connected" : "Unknown");

			ImGui::NewLine();

			if (g_context.m_running) {
				if (ImGui::Button("Stop", ImVec2(100, 50))) g_context.stopProtection();
				if (g_context.m_protectionState == ProtectionStates::Idle) {
					ImGui::SameLine();
					if (ImGui::Button("Start Discord", ImVec2(150, 50))) {
						g_discord->startSuspendedDiscord(DiscordType::Discord);
					}
				}
			}
			else {
				if (ImGui::Button("Start", ImVec2(100, 50))) g_context.startProtection();
			}

			ImGui::NewLine();

			static bool autoStart = g_config->read<bool>("auto_start");
			static bool autoStartDiscord = g_config->read<bool>("auto_start_discord");
			if (ImGui::Checkbox("Auto start Protection", &autoStart)) {
				g_config->write<bool>("auto_start", autoStart);
			}
			if (ImGui::Checkbox("Auto start Discord", &autoStartDiscord)) {
				g_config->write<bool>("auto_start_discord", autoStartDiscord);
			}

			ImGui::EndChild();
		}
	}

	void AccountTab() {
		if (ImGui::BeginChild("AccountTab")) {
			//TODO merge with existing code
			static std::string info;
			static std::future<void> getInfoAsync = std::async(std::launch::async, []() {
				info = Discord::getUserInfo(g_secureKV->read("token", g_context.kd));
			});

			ImGui::Text("Your account:");
			ImGui::NewLine();

			ImGui::Text(info.empty() ? "Getting user info..." : info.c_str());

			ImGui::NewLine();

			//TODO Red & confirmation button
			if (ImGui::Button("Remove token")) {
				g_secureKV->reopenFile(true);
				MessageBoxA(NULL, "The token has been removed.\nPlease restart Discord Token Protector", "Discord Token Protector", MB_ICONINFORMATION | MB_OK);
				ExitProcess(0);
			}

			ImGui::EndChild();
		}
	}

	void SettingsTab() {
		if (ImGui::BeginChild("SettingsTab")) {
			ImGui::Text("Current encryption mode: %s", 
				(g_context.kd.type == EncryptionType::HWID) ? "HWID" :
				(g_context.kd.type == EncryptionType::Password) ? "Password" :
				(g_context.kd.type == EncryptionType::HWIDAndPassword) ? "HWID and Password" : "Unknown");

			ImGui::NewLine();

			if (ImGui::CollapsingHeader("Change the encryption mode")) {
				ImGui::Indent(16.f);

				//TODO merge with the setup one?
				static int selectedEncryptionMode = 1;

				static char passwordInput[256];
				static char password2Input[256];

				static float hashTime = 0.5f;

				static std::future<void> asyncReencrypt;
				static bool reencryptionProcess = false;

				auto reset = [&]() {
					SecureZeroMemory(passwordInput, 256);
					SecureZeroMemory(password2Input, 256);
				};

				ImGui::Combo("New encryption mode", &selectedEncryptionMode, "Password-less (HWID)\0Password\0Password + HWID\0\0");

				if (selectedEncryptionMode > 0) {
					ImGui::InputText("Password", passwordInput, 256, ImGuiInputTextFlags_Password);
					ImGui::InputText("Confirm Password", password2Input, 256, ImGuiInputTextFlags_Password);
					ImGui::SliderFloat("Hash Time", &hashTime, 0.1f, 3.0f, "%.2fs");
					ImGui::SameLine();
					ImGui::TextTooltip("(?)", "This corresponds to the time taken to hash your password. "
						"The longer it is, the more time it will take to unlock the container. But it\'ll "
						"also make it more secure against bruteforcing.");
				}
				else {
					reset();
				}
				ImGui::NewLine();

				if (reencryptionProcess) {
					ImGui::PushItemFlag(ImGuiItemFlags_Disabled, true);
					ImGui::Button("Reencrypting...", ImVec2(ImGui::GetWindowWidth() - 30, 30));
					ImGui::PopItemFlag();
					ImGui::LinearIndeterminateBar("progressindicator", ImVec2(ImGui::GetWindowWidth() - 22, 10));
				}
				else {
					if (ImGui::Button("Reencrypt!", ImVec2(ImGui::GetWindowWidth() - 30, 30))) {
						if (selectedEncryptionMode == 0 && g_context.kd.type == EncryptionType::HWID) {
							MessageBoxA(NULL, "Please select a different mode.", "Discord Token Protector", MB_ICONWARNING | MB_OK);
						}
						else if (selectedEncryptionMode != 0 && strcmp(passwordInput, password2Input) != 0) {
							//TODO proper thing in ImGui
							MessageBoxA(NULL, "Passwords aren\'t identical.", "Discord Token Protector", MB_ICONWARNING | MB_OK);
						}
						else if (selectedEncryptionMode != 0 && strlen(passwordInput) < 6) {//TODO change?
							MessageBoxA(NULL, "The password must have at least 6 characters.", "Discord Token Protector", MB_ICONWARNING | MB_OK);
						}
						else {
							//TODO merge with existing code ?
							asyncReencrypt = std::async(std::launch::async, [](secure_string password) {
								KeyData newKeydata;

								if (selectedEncryptionMode == 0) {
									newKeydata = HWID_kd;
								}
								else {
									if (selectedEncryptionMode == 1)
										newKeydata.type = EncryptionType::Password;
									if (selectedEncryptionMode == 2)
										newKeydata.type = EncryptionType::HWIDAndPassword;

									float singleHashTime = hashTime / 2;
									uint32_t iterations_key = 0;
									uint32_t iterations_iv = 0;

									newKeydata.key = Crypto::derivateKey(password, CryptoPP::AES::MAX_KEYLENGTH, iterations_key, singleHashTime);
									newKeydata.iv = Crypto::derivateKey(password, CryptoPP::AES::BLOCKSIZE * 16, iterations_iv, singleHashTime);

									//TODO add check if iterations == 0, (this shouldn't happen)

									g_config->write("iterations_key", iterations_key);
									g_config->write("iterations_iv", iterations_iv);
								}

								g_secureKV->reencrypt(g_context.kd, newKeydata);
								g_context.kd = newKeydata;

								reencryptionProcess = false;
							}, secure_string(passwordInput));
							reencryptionProcess = true;
						}
						reset();
					}
				}
				ImGui::Unindent(16.f);
			}

			ImGui::NewLine();

			ImGui::Separator();

			ImGui::NewLine();

#if defined(_PROD) && !defined(DISABLE_AUTOSTART)
			static bool startWithWindows = g_context.m_isAutoStarting;
			if (ImGui::Checkbox("Start with Windows", &startWithWindows)) {
				if (startWithWindows)
					g_context.installAutoStart();
				else
					g_context.uninstallAutoStart();
				startWithWindows = g_context.m_isAutoStarting = g_context.isAutoStarting();
			}
#endif
			ImGui::EndChild();
		}
	}

	LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
		switch (msg) {
		case WM_DTPMSG:
			switch (lParam) {
			case WM_LBUTTONDBLCLK:
			case WM_LBUTTONUP:
				ShowWindow(mainHwnd, SW_SHOW);
				return 0;
			case WM_RBUTTONDOWN:
				POINT cursorPos;
				GetCursorPos(&cursorPos);
				if (TrackPopupMenu(trayMenu, TPM_RETURNCMD | TPM_NONOTIFY, cursorPos.x, cursorPos.y, 0, hwnd, NULL) == TRAY_ID_QUIT) {
					g_context.stopProtection();
					running = false;
				}
				return 0;
			default: break;
			}
		default: break;
		}
		return CallWindowProc(originalWndProc, hwnd, msg, wParam, lParam);
	}
}
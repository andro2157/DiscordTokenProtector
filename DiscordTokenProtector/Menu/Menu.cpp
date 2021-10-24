#include "Menu.h"
#include "FrameRateLimiter.h"
#include "Colors.h"
#include "ImGuiAddon.h"

#include "../Context.h"

#include "shellapi.h"
#include "../resource.h"

//#include <shellscalingapi.h>
//
//#pragma comment(lib, "Shcore.lib")

FrameRateLimiter g_fpslimit(FPS_MAX);

namespace Menu {
#define ConfigCheckbox(ui_name, config_name)\
	static bool checkbox_##config_name## = g_config->read<bool>(#config_name);\
	if (ImGui::Checkbox(ui_name, &checkbox_##config_name##)) g_config->write<bool>(#config_name, checkbox_##config_name##);

	ImFont* largeFont = nullptr;
	ImFont* smallFont = nullptr;
	ImFont* monospaceFont = nullptr;

	WNDPROC originalWndProc = nullptr;
	HWND mainHwnd = NULL;
	HMENU trayMenu = NULL;

	bool running = true;

	EasyAsync stopAsync([]() {
		g_context.stopProtection();
	});

	EasyAsync startAsync([]() {
		g_context.startProtection();
	});

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
		//SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE);

		glfwSetErrorCallback(glfw_error_callback);
		if (!glfwInit()) {
			FATALERROR("Failed to init GLFW!");
		}

		// GL 3.0 + GLSL 130
		const char* glsl_version = "#version 130";
		glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
		glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
		//glfwWindowHint(GLFW_SCALE_TO_MONITOR, GLFW_TRUE);

		GLFWwindow* window = glfwCreateWindow(600, 375, "Discord Token Protector " VER, NULL, NULL);
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

		stopAsync.wait();

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

		static char passwordInput[256];//TODO FIX the password is still in the memory after the SecureZeroMemory.
		static char pinInput[9];

		bool enterUnlock = false;

		//TODO merge with existing code
#ifdef YUBIKEYSUPPORT
		static std::unique_ptr<Crypto::Yubi> yk;
		static std::string ykInitError;
		static int ykRetries = 0;
#endif
		bool ykCanContinue = false;

		if (g_context.encryptionType_cache == EncryptionType::HWIDAndPassword || g_context.encryptionType_cache == EncryptionType::Password) {
			ImGui::TextWrapped("Please enter the password of the container:");

			enterUnlock = ImGui::InputText("##Password", passwordInput, 256, ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue);
		}
#ifdef YUBIKEYSUPPORT
		else if (g_context.encryptionType_cache == EncryptionType::Yubi) {
			static EasyAsync ykDetectAsync([]() {
				ykInitError.clear();
				try {
					yk = std::make_unique<Crypto::Yubi>();
					ykRetries = yk->getRetryCount();
				}
				catch (std::exception& e) {
					ykInitError = e.what();
				}
			}, true);

			if (ykDetectAsync.isRunning()) {
				ImGui::NewLine();
				ImGui::Text("Searching YubiKey...");
				ImGui::LinearIndeterminateBar("progressindicator", ImVec2(ImGui::GetWindowWidth() - 22, 10));
			}
			else {
				if (ykInitError.empty() && yk) {
					ImGui::TextWrapped("Found : %s", yk->getModelName().c_str());
					ImGui::SameLine();
					if (ImGui::Button("Refresh"))
						ykDetectAsync.start();

					enterUnlock = ImGui::InputText("PIV PIN", pinInput, 9, ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue);
					if (ykRetries != -1)
						ImGui::TextColored(Colors::Red, "Retries left : %d", ykRetries);

					ykCanContinue = pinInput[0] != '\000';
				}
				else {
					ImGui::NewLine();
					ImGui::TextWrapped("Error : %s", ykInitError.c_str());
					ImGui::TextWrapped("Please connect your YubiKey.");
					if (ImGui::Button("Refresh"))
						ykDetectAsync.start();
				}
			}
		}
#endif

		ImGui::NewLine();

		static EasyAsync unlockAsync([]() {
			secure_string password(passwordInput);
#ifdef YUBIKEYSUPPORT
			secure_string pin(pinInput);
#endif

			SecureZeroMemory(passwordInput, 256);
			SecureZeroMemory(pinInput, 9);

#ifdef YUBIKEYSUPPORT
			if (g_context.encryptionType_cache == EncryptionType::Yubi) {
				try {
					ykRetries = yk->authentificate(pin);
					if (ykRetries != -1) {
						MessageBoxA(NULL, "Invalid PIN", "Discord Token Protector", MB_ICONWARNING | MB_OK);
						return;
					}

					password = yk->signData(Crypto::Yubi::readKeyFile());
				}
				catch (std::exception& e) {
					ykRetries = yk->getRetryCount();
					MessageBoxA(NULL, e.what(), "Discord Token Protector", MB_ICONWARNING | MB_OK);
					return;
				}
			}
#endif

			uint32_t iterations_key = g_config->read<uint32_t>("iterations_key");
			uint32_t iterations_iv = g_config->read<uint32_t>("iterations_iv");
			//TODO add sanitary check of iterations

			g_context.kd.type = g_context.encryptionType_cache;
			g_context.kd.key = Crypto::derivateKey(password, CryptoPP::AES::MAX_KEYLENGTH, iterations_key);
			g_context.kd.iv = Crypto::derivateKey(password, CryptoPP::AES::BLOCKSIZE * 16, iterations_iv);
			g_context.kd.encrypt();

			secure_string token = g_secureKV->read("token", g_context.kd);
			if (token.empty()) {
				g_context.kd.reset();
				token.clear();

				//TODO proper ImGui thing
				MessageBoxA(NULL,
					(g_context.encryptionType_cache == EncryptionType::Yubi)
					? "Invalid YubiKey or corrupted message" :
					(g_context.encryptionType_cache == EncryptionType::Password)
					? "Invalid password" : "Invalid password or HWID",
					"Discord Token Protector", MB_ICONSTOP | MB_OK);
#ifdef YUBIKEYSUPPORT
				if (g_context.encryptionType_cache == EncryptionType::Yubi)
					ykRetries = yk->getRetryCount();
#endif
				return;
			}
			else if (Discord::getUserInfo(token).id.empty()) {
				MessageBoxA(NULL, "The token is invalid and has been removed from DTP.\
							Please check the log for more info.", "Discord Token Protector", MB_ICONSTOP | MB_OK);
				g_secureKV->reopenFile(true);//Reset
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
				startAsync.start();
		});

		if (unlockAsync.isRunning()) {
			ImGui::PushItemFlag(ImGuiItemFlags_Disabled, true);
			ImGui::Button("Unlocking...", ImVec2(ImGui::GetWindowWidth() - 30, 30));
			ImGui::PopItemFlag();
			ImGui::LinearIndeterminateBar("progressindicator", ImVec2(ImGui::GetWindowWidth() - 22, 10));
		}
		else if (g_context.encryptionType_cache != EncryptionType::Yubi || ykCanContinue) {
			if (ImGui::Button("Unlock", ImVec2(ImGui::GetWindowWidth() - 30, 30)) || enterUnlock) {
				unlockAsync.start();
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

		static bool discordAffiliationWarning = true;
		if (discordAffiliationWarning) {
			ImGui::TextColored(Colors::Red, "Disclamer");
			ImGui::NewLine();

			ImGui::TextWrapped("DTP is not affiliated with Discord.");
			ImGui::TextWrapped("DTP is in NO way responsible for what can happen on your Discord account.");
			ImGui::TextWrapped("Chances of getting terminated using DTP are very low, but"
				"please keep in mind that using a thirdparty software is against Discord\'s TOS.");


			ImGui::NewLine();

			if (ImGui::Button("I understand", ImVec2(ImGui::GetWindowWidth() - 30, 30))) {
				discordAffiliationWarning = false;
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
			static DiscordUserInfo info;
			static EasyAsync getInfoAsync([]() {
				info = Discord::getUserInfo(Discord::getStoredToken(true));
			}, true);

			ImGui::TextWrapped("We found this account:");
			ImGui::NewLine();

			if (getInfoAsync.isRunning()) {
				ImGui::Text("Getting user info...");
			}
			else {
				ImGui::Text("Username : %s", info.fullUsername.c_str());
				ImGui::Text("id : %s", info.id.c_str());
			}

			ImGui::NewLine();

			ImGui::TextWrapped("This account\'s token will be secured, and you\'ll be automatically "
				"logged into this account when launching Discord.");

			ImGui::NewLine();

			if (!getInfoAsync.isRunning()) {
				if (ImGui::Button("It\'s correct!", ImVec2(ImGui::GetWindowWidth() - 30, 30))) {
					g_context.state = State::MakeNewPassword;
				}
			}
		}
		else if (g_context.state == State::MakeNewPassword ||
			g_context.encryptionType_cache == EncryptionType::Unknown) {
			static int selectedEncryptionMode = 1;

			static char passwordInput[256];
			static char password2Input[256];
			static char pinInput[9];

			static float hashTime = 0.5f;

#ifdef YUBIKEYSUPPORT
			static std::unique_ptr<Crypto::Yubi> yk;
			static std::string ykInitError;
			static int ykRetries = 0;
#endif
			bool ykCanContinue = false;

			auto reset = [&]() {
				SecureZeroMemory(passwordInput, 256);
				SecureZeroMemory(password2Input, 256);
#ifdef YUBIKEYSUPPORT
				SecureZeroMemory(pinInput, 9);
#endif
			};

			ImGui::TextWrapped("Let\'s now setup the secure container that will store your token!\n"
				"Please chose the mode:");
#ifdef YUBIKEYSUPPORT
			ImGui::Combo("Encryption Mode", &selectedEncryptionMode, "Password-less (HWID)\0Password\0Password + HWID\0YubiKey\0\0");
#else
			ImGui::Combo("Encryption Mode", &selectedEncryptionMode, "Password-less (HWID)\0Password\0Password + HWID\0\0");
#endif		
			if (selectedEncryptionMode == 0) {
				ImGui::TextColored(Colors::Red, "Warning!");
				ImGui::TextWrapped("This mode doesn\'t require a password, but the secure container can be easily "
					"decrypted by a program running on this computer using your user account. "
					"For example : a malware, someone accessing your pc, etc");
				reset();
			}
			else if (selectedEncryptionMode == 1 || selectedEncryptionMode == 2) {
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
#ifdef YUBIKEYSUPPORT
			else if (selectedEncryptionMode == 3) {
				static EasyAsync ykDetectAsync([]() {
					ykInitError.clear();
					try {
						yk = std::make_unique<Crypto::Yubi>();
						ykRetries = yk->getRetryCount();
					}
					catch (std::exception& e) {
						ykInitError = e.what();
					}
				}, true);

				if (ykDetectAsync.isRunning()) {
					ImGui::NewLine();
					ImGui::Text("Searching YubiKey...");
					ImGui::LinearIndeterminateBar("progressindicator", ImVec2(ImGui::GetWindowWidth() - 22, 10));
				}
				else {
					if (ykInitError.empty() && yk) {
						ImGui::TextWrapped("Found : %s", yk->getModelName().c_str());
						ImGui::SameLine();
						if (ImGui::Button("Refresh"))
							ykDetectAsync.start();

						ImGui::TextWrapped("Please make sure you have a certificate in the card authentification slot!");
						ImGui::SameLine();
						ImGui::TextTooltip("(?)", "Using the YubiKey Manager app, you can generate a card authentification certificate. "
							"A random message signed with this certificate is going to be used as the encryption key. "
							"A guide can be found on the Github repo.");

						ImGui::InputText("PIV PIN", pinInput, 9, ImGuiInputTextFlags_Password);
						ImGui::SameLine();
						ImGui::TextTooltip("(?)", "This is the PIN used in PIV (Personal Identity Verification). "
							"By default, it is \"123456\", we strongly recommend you updating it with the YubiKey Manager app. "
							"THIS IS DIFFERENT FROM THE FIDO PIN!");

						if (ykRetries != -1)
							ImGui::TextColored(Colors::Red, "Retries left : %d", ykRetries);

						ImGui::SliderFloat("Hash Time", &hashTime, 0.1f, 3.0f, "%.2fs");
						ImGui::SameLine();
						ImGui::TextTooltip("(?)", "This corresponds to the time taken to hash your password. "
							"The longer it is, the more time it will take to unlock the container. But it\'ll "
							"also make it more secure against bruteforcing.");

						ykCanContinue = pinInput[0] != '\000';
					}
					else {
						ImGui::NewLine();
						ImGui::TextWrapped("Error : %s", ykInitError.c_str());
						ImGui::TextWrapped("Please connect your YubiKey.");

						if (ImGui::Button("Refresh"))
							ykDetectAsync.start();
					}
				}
			}
#endif
			if (selectedEncryptionMode == 0 || selectedEncryptionMode == 2) {
				ImGui::TextWrapped("Please also keep in mind that, with the HWID one, "
					"the container content will be lost if you change your "
					"Windows user account, if you reinstall Windows, or if you change your computer.");
			}


			static EasyAsync storeTokenAsync([&reset]() {
				secure_string password(passwordInput);
#ifdef YUBIKEYSUPPORT
				secure_string pin(pinInput);
#endif
				reset();

				if (selectedEncryptionMode == 0) {
					g_context.kd = HWID_kd;
				}
				else {
					if (selectedEncryptionMode == 1)
						g_context.kd.type = EncryptionType::Password;
					else if (selectedEncryptionMode == 2)
						g_context.kd.type = EncryptionType::HWIDAndPassword;
#ifdef YUBIKEYSUPPORT
					else if (selectedEncryptionMode == 3) {
						g_context.kd.type = EncryptionType::Yubi;
						try {
							ykRetries = yk->authentificate(pin);
							if (ykRetries != -1) {
								MessageBoxA(NULL, "Invalid PIN", "Discord Token Protector", MB_ICONWARNING | MB_OK);
								return;
							}

							password = yk->signData(Crypto::Yubi::generateKeyFile());
						}
						catch (std::exception& e) {
							ykRetries = yk->getRetryCount();
							MessageBoxA(NULL, e.what(), "Discord Token Protector", MB_ICONWARNING | MB_OK);
							return;
						}
					}
#endif

					float singleHashTime = hashTime / 2;
					uint32_t iterations_key = 0;
					uint32_t iterations_iv = 0;

					g_context.kd.key = Crypto::derivateKey(password, CryptoPP::AES::MAX_KEYLENGTH, iterations_key, singleHashTime);
					g_context.kd.iv = Crypto::derivateKey(password, CryptoPP::AES::BLOCKSIZE * 16, iterations_iv, singleHashTime);
					g_context.kd.encrypt();

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
				startAsync.start();
			});

			if (storeTokenAsync.isRunning()) {
				ImGui::PushItemFlag(ImGuiItemFlags_Disabled, true);
				ImGui::Button("Encrypting...", ImVec2(ImGui::GetWindowWidth() - 30, 30));
				ImGui::PopItemFlag();
				ImGui::LinearIndeterminateBar("progressindicator", ImVec2(ImGui::GetWindowWidth() - 22, 10));
			}
			else {
				if (selectedEncryptionMode != 3 || ykCanContinue) {
					if (ImGui::Button("Continue", ImVec2(ImGui::GetWindowWidth() - 30, 30))) {
						const bool passwordBasedEncryption = selectedEncryptionMode == 1 || selectedEncryptionMode == 2;
						if (passwordBasedEncryption && strcmp(passwordInput, password2Input) != 0) {
							//TODO proper thing in ImGui
							MessageBoxA(NULL, "Passwords aren\'t identical.", "Discord Token Protector", MB_ICONWARNING | MB_OK);
							reset();
						}
						else if (passwordBasedEncryption && strlen(passwordInput) < 6) {//TODO change?
							MessageBoxA(NULL, "The password must have at least 6 characters.", "Discord Token Protector", MB_ICONWARNING | MB_OK);
							reset();
						}
						else {
							storeTokenAsync.start();
						}
					}
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

			if (g_context.m_running) {
				if (g_context.m_protectionState == ProtectionStates::Checking) {
					ImGui::Text("Current status : Checking the integrity of Discord. (%d/%d)",
						g_context.integrityCheck.getProgress(), g_context.integrityCheck.getProgressTotal());

					ImGui::ProgressBar(
						static_cast<float>(g_context.integrityCheck.getProgress()) / static_cast<float>(g_context.integrityCheck.getProgressTotal())
					);
				}
				else if (g_context.m_protectionState == ProtectionStates::CheckIssues) {
					auto issues = g_context.integrityCheck.getIssues();
					ImGui::Text("Current status : Found %d issues!", issues.size());

					if (ImGui::BeginChild("##ISSUES", ImVec2(0, 100), true, ImGuiWindowFlags_AlwaysVerticalScrollbar)) {
						ImGui::Columns(2);
						ImGui::PushFont(smallFont);
						for (const auto& issue : issues) {
							ImGui::TextWrapped(issue.first.c_str());
							ImGui::NextColumn();
							ImGui::TextWrapped(issue.second.c_str());
							ImGui::NextColumn();
						}
						ImGui::PopFont();
						ImGui::Columns(1);

						ImGui::EndChild();
					}

					if (ImGui::Button("Ignore, start anyway")) {
						g_context.m_protectionState = ProtectionStates::Injecting;
					}
					ImGui::SameLine();
					if (ImGui::Button("Stop Discord launch")) {
						g_context.m_protectionState = ProtectionStates::Stop;
					}
				}
				else {
					ImGui::Text("Current status : %s", g_context.getCurrentStateString().c_str());
				}
			}
			
			ImGui::NewLine();

			if (g_context.m_protectionState != ProtectionStates::CheckIssues) {
				if (startAsync.isRunning()) {
					ImGui::PushItemFlag(ImGuiItemFlags_Disabled, true);
					ImGui::Button("Starting...", ImVec2(100, 50));
					ImGui::PopItemFlag();
					ImGui::LinearIndeterminateBar("startprogress", ImVec2(108, 10));
				} else if (stopAsync.isRunning()) {//startAsync & stopAsync shouldn't be running at the same time
					ImGui::PushItemFlag(ImGuiItemFlags_Disabled, true);
					ImGui::Button("Stopping...", ImVec2(100, 50));
					ImGui::PopItemFlag();
					ImGui::LinearIndeterminateBar("stopprogress", ImVec2(108, 10));
				}
				else if (g_context.m_running) {
					if (ImGui::Button("Stop", ImVec2(100, 50)))
						stopAsync.start();
					if (g_context.m_protectionState == ProtectionStates::Idle) {
						ImGui::SameLine();
						if (ImGui::Button("Start Discord", ImVec2(150, 50))) {
							g_discord->startSuspendedDiscord(DiscordType::Discord);
						}
					}
				}
				else {
					if (ImGui::Button("Start", ImVec2(100, 50)))
						startAsync.start();
				}
			}

			ImGui::NewLine();

			ConfigCheckbox("Auto start Protection", auto_start);
			ConfigCheckbox("Auto start Discord", auto_start_discord);

			ImGui::EndChild();
		}
	}

	void AccountTab() {
		if (ImGui::BeginChild("AccountTab")) {
			//TODO merge with existing code
			static DiscordUserInfo info;
			static EasyAsync getInfoAsync([]() {
				info = Discord::getUserInfo(g_secureKV->read("token", g_context.kd));
			}, true);

			ImGui::Text("Your account:");
			ImGui::SameLine();
			if (ImGui::Button("Refresh")) getInfoAsync.start();

			ImGui::NewLine();

			if (info.id.empty()) {
				ImGui::Text("Getting user info...");
			}
			else {
				ImGui::Text("Username : %s", info.fullUsername.c_str());
				ImGui::Text("id : %s", info.id.c_str());

				if (info.mfa) {
					ImGui::TextColored(Colors::Green, "Your account is secured with 2FA!");
				}
				else {
					ImGui::TextColored(Colors::Red, "It is recommended to secure your account with 2FA!");
					if (ImGui::Button("Secure it!")) {
						ShellExecute(0, 0, TEXT("https://support.discord.com/hc/en-us/articles/219576828-Setting-up-Two-Factor-Authentication"), 0, 0, SW_SHOW);
					}
				}
			}

			ImGui::NewLine();

			if (ImGui::CollapsingHeader("Change the account password")) {
				/*
				Using std::unique_ptr<secure_string> instead of char[] doesn't seem to fix the issue with
				the content not being zero'd.
				It might be due to ImGui that copies the content
				*/
				static std::unique_ptr<secure_string> passwordInput;
				static std::unique_ptr<secure_string> newPasswordInput;
				static std::unique_ptr<secure_string> mfaInput;

				auto resetInputs = [&]() {
					passwordInput = std::make_unique<secure_string>(256, '\000');
					newPasswordInput = std::make_unique<secure_string>(256, '\000');
					mfaInput = std::make_unique<secure_string>(10, '\000');
				};

				if (!passwordInput || !newPasswordInput) resetInputs();

				static int newRandomPassword = 0;
				static int randomPasswordLen = 16;

				static EasyAsync asyncChangePassword([&]() {
					removeTaillingNulls(*passwordInput);
					removeTaillingNulls(*newPasswordInput);
					removeTaillingNulls(*mfaInput);

					secure_string error;
					if (Discord::changePassword(g_secureKV->read("token", g_context.kd),
						*passwordInput, *newPasswordInput, *mfaInput, error)) {
						g_secureKV->write("token", error, g_context.kd);
						g_logger.info(newPasswordInput->c_str());

						if (newRandomPassword == 0) {
							MessageBoxA(NULL, "Your new password has been copied to your clipboard. Please restart Discord to log back in!", "Success", MB_OK | MB_ICONINFORMATION);
							ImGui::SetClipboardText(newPasswordInput->c_str());
						}
						else {
							MessageBoxA(NULL, "Successfully changed the password", "Success", MB_OK | MB_ICONINFORMATION);
						}

						g_logger.info("Successfully changed password!");
					}
					else {
						MessageBoxA(NULL, error.c_str(), "Discord Token Protector", MB_ICONWARNING | MB_OK);
					}

					resetInputs();
				});

				ImGui::InputText("Current Password", passwordInput->data(), 256, ImGuiInputTextFlags_Password);

				//If we change the mode, we reset the new password input
				if (ImGui::Combo("New password mode", &newRandomPassword, "Random (recommended)\0Manual\0\0"))
					newPasswordInput = std::make_unique<secure_string>(265, '\000');

				if (newRandomPassword == 0) {
					ImGui::SliderInt("New password length", &randomPasswordLen, 12, 32);
				}
				else {
					ImGui::InputText("New Password", newPasswordInput->data(), 256, ImGuiInputTextFlags_Password);
				}

				if (info.mfa) {
					ImGui::InputText("2FA code", mfaInput->data(), 10);
				}

				if (asyncChangePassword.isRunning()) {
					ImGui::PushItemFlag(ImGuiItemFlags_Disabled, true);
					ImGui::Button("Changing password...", ImVec2(ImGui::GetWindowWidth() - 30, 30));
					ImGui::PopItemFlag();
					ImGui::LinearIndeterminateBar("progressindicator", ImVec2(ImGui::GetWindowWidth() - 22, 10));
				}
				else {
					if (ImGui::Button("Change!", ImVec2(ImGui::GetWindowWidth() - 30, 30))) {
						if (newRandomPassword == 0)
							newPasswordInput = std::make_unique<secure_string>(CryptoUtils::secureRandomString(std::clamp(randomPasswordLen, 12, 32)));
						if (!info.mfa)
							mfaInput->clear();

						asyncChangePassword.start();
					}
				}
			}

			ImGui::NewLine();

			//TODO Red & confirmation button
			if (ImGui::Button("Remove Token")) {
				g_secureKV->reopenFile(true);
				MessageBoxA(NULL, "The token has been removed.\nPlease restart Discord Token Protector", "Discord Token Protector", MB_ICONINFORMATION | MB_OK);
				ExitProcess(0);
			}

			ImGui::EndChild();
		}
	}

	void SettingsTab() {
		if (ImGui::BeginChild("SettingsTab")) {
			if (ImGui::CollapsingHeader("Integrity Check")) {
				ImGui::TextWrapped("Checks the integrity of the Discord installation before launching it.");
				ConfigCheckbox("Enable integrity check", integrity);

				ConfigCheckbox("Check file hashes", integrity_checkhash);
				ImGui::SameLine();
				ImGui::TextTooltip("(?)", "This will compare the file hashes of your Discord installation "
				"with the known ones. The hashes for your Discord version needs to be on the git repo.");

				ConfigCheckbox("Check digital signature", integrity_checkexecutable);
				ImGui::SameLine();
				ImGui::TextTooltip("(?)", "This will check the digital signature of every executable files "
				"(.exe and .dll)");

				ConfigCheckbox("Check modules", integrity_checkmodule);
				ImGui::SameLine();
				ImGui::TextTooltip("(?)", "This will check the NodeJS modules loaded by Discord");

				ConfigCheckbox("Check resources", integrity_checkresource);
				ImGui::SameLine();
				ImGui::TextTooltip("(?)", "This will check the resources scripts");

				ConfigCheckbox("Check scripts", integrity_checkscripts);
				ImGui::SameLine();
				ImGui::TextTooltip("(?)", "This will check every JS scripts for known malware signatures");

				ConfigCheckbox("Allow BetterDiscord", integrity_allowbetterdiscord);

				ConfigCheckbox("Don\'t use cached hashes", integrity_redownloadhashes);
				ImGui::SameLine();
				ImGui::TextTooltip("(?)", "Discord file hashes will be redownloaded each time");
			}

			ImGui::NewLine();
			ImGui::Separator();
			ImGui::NewLine();

			ImGui::Text("Current encryption mode: %s", 
				(g_context.kd.type == EncryptionType::HWID) ? "HWID" :
				(g_context.kd.type == EncryptionType::Password) ? "Password" :
				(g_context.kd.type == EncryptionType::HWIDAndPassword) ? "HWID and Password" :
				(g_context.kd.type == EncryptionType::Yubi) ? "YubiKey" : "Unknown");

			ImGui::NewLine();

			if (ImGui::CollapsingHeader("Change the encryption mode")) {
				ImGui::Indent(16.f);

				//TODO merge with the setup one?
				static int selectedEncryptionMode = 1;

				static char passwordInput[256];
				static char password2Input[256];
				static char pinInput[9];

				static float hashTime = 0.5f;

#ifdef YUBIKEYSUPPORT
				static std::unique_ptr<Crypto::Yubi> yk;
				static std::string ykInitError;
				static int ykRetries = 0;
#endif
				bool ykCanContinue = false;

				auto reset = [&]() {
					SecureZeroMemory(passwordInput, 256);
					SecureZeroMemory(password2Input, 256);
					SecureZeroMemory(pinInput, 9);
				};

#ifdef YUBIKEYSUPPORT
				ImGui::Combo("New encryption mode", &selectedEncryptionMode, "Password-less (HWID)\0Password\0Password + HWID\0YubiKey\0\0");
#else
				ImGui::Combo("New encryption mode", &selectedEncryptionMode, "Password-less (HWID)\0Password\0Password + HWID\0\0");
#endif

				if (selectedEncryptionMode == 1 || selectedEncryptionMode == 2) {
					ImGui::InputText("Password", passwordInput, 256, ImGuiInputTextFlags_Password);
					ImGui::InputText("Confirm Password", password2Input, 256, ImGuiInputTextFlags_Password);
					ImGui::SliderFloat("Hash Time", &hashTime, 0.1f, 3.0f, "%.2fs");
					ImGui::SameLine();
					ImGui::TextTooltip("(?)", "This corresponds to the time taken to hash your password. "
						"The longer it is, the more time it will take to unlock the container. But it\'ll "
						"also make it more secure against bruteforcing.");
				}
#ifdef YUBIKEYSUPPORT
				else if (selectedEncryptionMode == 3) {
					//TODO MERGE WITH THE SETUP!!!!
					static EasyAsync ykDetectAsync([]() {
						ykInitError.clear();
						try {
							yk = std::make_unique<Crypto::Yubi>();
							ykRetries = yk->getRetryCount();
						}
						catch (std::exception& e) {
							ykInitError = e.what();
						}
					}, true);

					if (ykDetectAsync.isRunning()) {
						ImGui::NewLine();
						ImGui::Text("Searching YubiKey...");
						ImGui::LinearIndeterminateBar("progressindicator", ImVec2(ImGui::GetWindowWidth() - 22, 10));
					}
					else {
						if (ykInitError.empty() && yk) {
							ImGui::TextWrapped("Found : %s", yk->getModelName().c_str());
							ImGui::SameLine();
							if (ImGui::Button("Refresh"))
								ykDetectAsync.start();

							ImGui::TextWrapped("Please make sure you have a certificate in the card authentification slot!");
							ImGui::SameLine();
							ImGui::TextTooltip("(?)", "Using the YubiKey Manager app, you can generate a card authentification certificate. "
								"A random message signed with this certificate is going to be used as the encryption key. "
								"A guide can be found on the Github repo.");

							ImGui::InputText("PIV PIN", pinInput, 9, ImGuiInputTextFlags_Password);
							ImGui::SameLine();
							ImGui::TextTooltip("(?)", "This is the PIN used in PIV (Personal Identity Verification). "
								"By default, it is \"123456\", we strongly recommend you updating it with the YubiKey Manager app. "
								"THIS IS DIFFERENT FROM THE FIDO PIN!");

							if (ykRetries != -1)
								ImGui::TextColored(Colors::Red, "Retries left : %d", ykRetries);

							ImGui::SliderFloat("Hash Time", &hashTime, 0.1f, 3.0f, "%.2fs");
							ImGui::SameLine();
							ImGui::TextTooltip("(?)", "This corresponds to the time taken to hash your password. "
								"The longer it is, the more time it will take to unlock the container. But it\'ll "
								"also make it more secure against bruteforcing.");

							ykCanContinue = pinInput[0] != '\000';
						}
						else {
							ImGui::NewLine();
							ImGui::TextWrapped("Error : %s", ykInitError.c_str());
							ImGui::TextWrapped("Please connect your YubiKey.");

							if (ImGui::Button("Refresh"))
								ykDetectAsync.start();
						}
					}
				}
#endif
				else {
					reset();
				}
				ImGui::NewLine();

				static EasyAsync reencryptAsync([&reset]() {
					//TODO merge with existing code ?

					secure_string password(passwordInput);
#ifdef YUBIKEYSUPPORT
					secure_string pin(pinInput);
#endif
					reset();

					KeyData newKeydata;

					if (selectedEncryptionMode == 0) {
						newKeydata = HWID_kd;
					}
					else {
						if (selectedEncryptionMode == 1)
							newKeydata.type = EncryptionType::Password;
						else if (selectedEncryptionMode == 2)
							newKeydata.type = EncryptionType::HWIDAndPassword;
#ifdef YUBIKEYSUPPORT
						else if (selectedEncryptionMode == 3) {
							newKeydata.type = EncryptionType::Yubi;
							try {
								ykRetries = yk->authentificate(pin);
								if (ykRetries != -1) {
									MessageBoxA(NULL, "Invalid PIN", "Discord Token Protector", MB_ICONWARNING | MB_OK);
									return;
								}

								password = yk->signData(Crypto::Yubi::generateKeyFile());
							}
							catch (std::exception& e) {
								ykRetries = yk->getRetryCount();
								MessageBoxA(NULL, e.what(), "Discord Token Protector", MB_ICONWARNING | MB_OK);
								return;
							}
						}
#endif

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
					g_context.kd.encrypt();

					MessageBoxA(NULL, "Successfully reencrypted!", "Success", MB_OK | MB_ICONINFORMATION);
				});

				if (reencryptAsync.isRunning()) {
					ImGui::PushItemFlag(ImGuiItemFlags_Disabled, true);
					ImGui::Button("Reencrypting...", ImVec2(ImGui::GetWindowWidth() - 30, 30));
					ImGui::PopItemFlag();
					ImGui::LinearIndeterminateBar("progressindicator", ImVec2(ImGui::GetWindowWidth() - 22, 10));
				}
				else if (selectedEncryptionMode != 3 || ykCanContinue) {
					if (ImGui::Button("Reencrypt!", ImVec2(ImGui::GetWindowWidth() - 30, 30))) {
						const bool passwordBasedEncryption = selectedEncryptionMode == 1 || selectedEncryptionMode == 2;

						if (selectedEncryptionMode == 0 && g_context.kd.type == EncryptionType::HWID) {
							MessageBoxA(NULL, "Please select a different mode.", "Discord Token Protector", MB_ICONWARNING | MB_OK);
							reset();
						}
						else if (passwordBasedEncryption && strcmp(passwordInput, password2Input) != 0) {
							//TODO proper thing in ImGui
							MessageBoxA(NULL, "Passwords aren\'t identical.", "Discord Token Protector", MB_ICONWARNING | MB_OK);
							reset();
						}
						else if (passwordBasedEncryption && strlen(passwordInput) < 6) {//TODO change?
							MessageBoxA(NULL, "The password must have at least 6 characters.", "Discord Token Protector", MB_ICONWARNING | MB_OK);
							reset();
						}
						else {
							reencryptAsync.start();
						}
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
					stopAsync.start();
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
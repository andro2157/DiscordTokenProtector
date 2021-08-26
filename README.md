# Discord Token Protector
#### Protect your Discord token from malicious grabbers!

![Main Workflow](https://github.com/andro2157/DiscordTokenProtector/actions/workflows/msbuild.yml/badge.svg)

<p align="center">
  <img width="500" src="Assets/DiscordTokenProtectorUI.png">
</p>

This project is still under development! You might face some unstability issues!\
This is in **NO** way a perfect solution against Discord token grabbers.
But this will protect you against most (nearly every) token grabbers.

**Any targeted attack against DiscordTokenProtector can bypass this protection!**

## Features

#### ✅ Protect your self from most token grabbers
#### ✅ Securely store your Discord token in an encrypted file
#### ✅ Change your Discord password in one-click
#### ✅ Check the integrity of your Discord installation on launch (BetterDiscord is supported)
#### ✅ Check scripts for known malwares *(eg AnarchyGrabber3)*

## Installation / Update

### Download the lastest release **[HERE](https://github.com/andro2157/DiscordTokenProtector/releases)**

* Start DiscordTokenProtectorSetup.exe
* Select between Normal and NoStartup installation
* **[Set it up](Setup.md)**
* Enjoy!

## What does it do?

Here's a little diagram on how it works:

<p align="center">
  <img width="800" src="Assets/how_does_it_work.jpg">
</p>

It basically removes the `Local Storage` and `Session Storage` directories from `%appdata%\Discord`.
These directories can store your Discord token (used to authentificate you).
Most of the grabbers look for your token there. Therefore, by removing these directories you can avoid getting grabbed.\
Your Discord token is stored in a secure container encrypted with AES-256.

## Some stuff to consider

* By removing these directories, Discord cannot store any local settings.
Meaning that all of your client-specific settings will be removed each time you start Discord. (eg. keybinds, default audio device, ...)\
**BUT**, all of the server-sided settings are still saved. (users descriptions, language, dark mode, ...)

* Discord canary might not work properly. These builds doesn't support handoff login.

* Again, this is a project in development, you might face some unstabilities (crash, discord not launching, ...). Please report these issues on this repo.

* Some anti-virus flags DiscordTokenProtector because it can start with Windows, and that it can inject payload into Discord.
These activities are suspicious for AVs. I provided builds without the auto-startup, it reduces the amount of false-flag.

* DiscordTokenProtector doesn't seem to work well on Windows 7

* Integrity check hashes are uploaded manually, therefore you might get an error message saying that it's unable to get the hashes. Please open a ticket if it says so!

## Compilation

To compile, it's recommended to use [vcpkg](https://github.com/microsoft/vcpkg) for the libraries

### Step 1: Installing vcpkg
*You can skip this step if you already have it*
```
git clone https://github.com/microsoft/vcpkg
cd vcpkg
bootstrap-vcpkg.bat -disableMetrics
```
Start a new cmd as admin in the `vcpkg` folder and type:
```
vcpkg integrate install
```

### Step 2: Installing the libraries
Copy and paste this (in the vcpkg directory if you don't have it in the PATH)
```
vcpkg install imgui:x86-windows-static imgui[glfw-binding]:x86-windows-static imgui[opengl3-gl3w-binding]:x86-windows-static imgui[win32-binding]:x86-windows-static nlohmann-json:x86-windows-static cryptopp:x86-windows-static curl:x86-windows-static polyhook2:x86-windows-static
```
*This process might take some time as it's building these libraries (for the static link)*

### Step 3: Cloning DiscordTokenProtector
```
git clone https://github.com/andro2157/DiscordTokenProtector
```

### Step 4: Open the project in VS
Open `DiscordTokenProtector.sln`

Everything should be setup, you just need to compile it with the `PROD` or `PROD-NOSTARTUP` config in **x86**.

*Note : C++17 is required to compile.*

## Credit

* [Discord](https://discord.com/)
* Ocornut for [ImGui](https://github.com/ocornut/imgui)
* Nlohmann for the [JSON lib](https://github.com/nlohmann/json)
* [CryptoPP](https://www.cryptopp.com/)
* Stevemk14ebr for [Polyhook v2](https://github.com/stevemk14ebr/PolyHook_2_0)
* [CUrl](https://curl.se/)

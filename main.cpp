#include <codecvt>
#include <iostream>
#include <locale>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif

#ifndef UNICODE
# define UNICODE
#endif

#include <windows.h>
#include <tlhelp32.h>

typedef std::vector<std::string> Modules;

std::string utf16_to_utf8(const std::wstring &wstr) {
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;
	return conv.to_bytes(wstr);
}

std::wstring utf8_to_utf16(const std::string &str)
{
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;
	return conv.from_bytes(str);
}

DWORD getProcessId(const std::string &name)
{
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(pe);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		std::cout << "getProcessId(): CreateToolhelp32Snapshot() returned INVALID_HANDLE_VALUE! Error: " << GetLastError();
		return 0;
	}

	const std::wstring wname = utf8_to_utf16(name);

	BOOL ok = Process32First(hSnap, &pe);
	while (ok) {
		if (wcscmp(pe.szExeFile, wname.c_str()) == 0) {
			return pe.th32ProcessID;
		}

		ok = Process32Next(hSnap, &pe);
	}

	CloseHandle(hSnap);

	return 0;
}

int isProcess64Bit(const DWORD &id)
{
	HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, id);
	if (!handle) {
		std::cout << "isProcess64Bit(): OpenProcess() returned NULL! Error: " << GetLastError();
		return -1;
	}

	BOOL isWow64Process;
	if (!IsWow64Process(handle, &isWow64Process)) {
		std::cout << "isProcess64Bit(): IsWow64Process() returned false! Error: " << GetLastError();
		CloseHandle(handle);
		return -1;
	}

	CloseHandle(handle);

	return !(isWow64Process || sizeof(void *) == 4);
}

Modules getModulesName(const DWORD &id)
{
	Modules modules;

	MODULEENTRY32 me;
	me.dwSize = sizeof(me);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, id);
	if (hSnap == INVALID_HANDLE_VALUE) {
		std::cout << "getModulesName(): CreateToolhelp32Snapshot() failed with error: " << GetLastError() << std::endl;
		return modules;
	}

	BOOL ok = Module32First(hSnap, &me);
	while (ok) {
		modules.push_back(utf16_to_utf8(me.szModule));
		ok = Module32Next(hSnap, &me);
	}

	CloseHandle(hSnap);

	return modules;
}

int main()
{
	std::cout << "Process name: ";

	std::string process_name;

	std::cin >> process_name;

	const DWORD process_id = getProcessId(process_name);
	if (process_id == 0) {
		std::cout << "Process not found!" << std::endl;
		return 1;
	}

	std::cout << "Process ID: " << process_id << std::endl;

	const int is64Bit = isProcess64Bit(process_id);
	if (is64Bit < 0) {
		std::cout << "Failed to detect process architecture!" << std::endl;
		return 2;
	}

	std::cout << "64 bit: " << is64Bit << std::endl;

	const Modules modules = getModulesName(process_id);
	if (modules.empty()) {
		std::cout << "No modules found!" << std::endl;
		return 3;
	}

	std::cout << std::endl << "----- Modules -----" << std::endl;

	for (const std::string &module : modules) {
		std::cout << module << std::endl;
	}

	return 0;
}

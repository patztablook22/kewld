/*
 * Konverzace Everybody Will Like Like server
 * C++ IRC with SSL encryption
 * "lol imma waste my time" ~ patz, d6022
 */

#define VERSION 95	// editing diz may cause unexpected behaviour

// needed libz:
// #include "libz/ur_package_manager.hpp"

// extern scriptz:
#include "core.hpp"


int main(int argc, const char *argv[])
{
	std::locale::global(std::locale("en_US.UTF-8"));
	std::wcout << L"Konverzace Everybody Will Like serv " << core::ver_echo(VERSION) << std::endl;
	switch (argc) {
	case 1:
		break;
	case 2:
		if (chdir(argv[1]) != 0) {
			std::string tmp(argv[1]);
			std::wcerr << L"ERR: failed to change working directory into " << std::wstring(tmp.begin(), tmp.end()) << L'\n';
		}
		break;
	default:
		std::string tmp(argv[0]);
		std::wcerr << L"usage: " << std::wstring(tmp.begin(), tmp.end()) << L" server_dir\n";
		exit(EXIT_FAILURE);
	}

	umask(077);
	core::cfg.init();
	core::usrz.init();
	core::serv.init();
	core::log.init();
	core::daemonize();
	core::serv.listener();

	return 0;
}

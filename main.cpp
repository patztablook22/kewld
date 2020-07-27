/*
 * Konverzace Everybody Will Like Like server
 * C++ IRC with SSL encryption
 * "lol imma waste my time" ~ patz, d6022
 */

#define VERSION 86	// editing diz may cause unexpected behaviour

// needed libz:
#include <iostream>	// IO stream
#include <fstream>	// file stream
#include <thread>	// std::thread
#include <csignal>	// std::signal
#include <locale>	// UTF-8
#include <string>	// std::string
#include <vector>	// std::vector
#include <cstring>	// sizeof etc.
#include <map>		// std::map
#include <sys/socket.h>	// socket
#include <arpa/inet.h>	// inet_addr
#include <unistd.h>	// close()
#include <sys/time.h>	// utime
#include <openssl/ssl.h>// ssl - base
#include <openssl/err.h>// ssl - errorz

// extern scriptz:
#include "core.hpp"


int main(int argc, const char *argv[])
{
	std::locale::global(std::locale("en_US.UTF-8"));
	std::wcout << L"Konverzace Everybody Will Like serv " << core::ver_echo(VERSION) << std::endl;

	std::string self(argv[0]);
	self.erase(self.find_last_of('/') + 1);

	core::cfg << self;
	signal(SIGINT, core::quit);
	core::serv.init();
	core::serv.listener();

	return 0;
}

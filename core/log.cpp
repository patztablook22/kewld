log::log()
:cio(true)
{
}

log::~log()
{
	if (fd.is_open())
		*this << L"logging stopped";
}

void log::init()
{
	std::string tmp(core::cfg.logfd.gval());
	fd.open(tmp, std::fstream::app);
	if (!fd.is_open()) {
		*this << L"ERR: failed to open log";
		exit(EXIT_FAILURE);
	}
	*this << L"logging into " + std::wstring(tmp.begin(), tmp.end()) + L" started";
}

void log::psss()
{
	cio = false;
}

void log::close()
{
	fd.close();
	psss();
}

void log::operator<<(std::wstring da_log)
{
	time_t tm = time(NULL);
	std::string tmp(ctime(&tm));
	fd << std::wstring(tmp.begin(), tmp.end() - 1) << L' ' << da_log << std::endl;
	if (cio) {
		if (da_log.substr(0, 5) == L"ERR: ")
			std::wcerr << da_log << std::endl;
		else
			std::wcout << da_log << std::endl;
	}

}

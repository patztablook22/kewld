void cfg::init()
{
	std::wstring buf;
	std::wifstream fd("serv.cfg");
	if (!fd.is_open()) {
		core::log << L"ERR: failed to open serv.cfg";
		exit(1);
	}
	core::log << L"importing configuration from serv.cfg";

	for (int line = 1; std::getline(fd, buf); line++) {
		buf = core::trim(buf);
		if (buf.size() == 0)
			continue;
		if (buf[0] == '#')
			continue;
		size_t pos = buf.find(61);
		if (pos == std::wstring::npos || pos == 0 || pos == buf.size() - 1) {
			core::log << L"ERR: cfg file invalid syntax: line " + std::to_wstring(line);
			exit(1);
		}
			std::wstring key(buf.begin(), buf.begin() + pos), val(buf.begin() + pos + 1, buf.end());
		key = core::trim(key);
		val = core::trim(val);
		
		if (extract.find(key) == extract.end()) {
			core::log << L"ERR: cfg file invalid key: line " + std::to_wstring(line);
			exit(1);
		}

		try {
			*(extract[key]) << val;
		} catch (int err) {
			std::wstring tmp(L"ERR: cfg file ");
			switch (err) {
			case 0:
				tmp += L"invalid type";
				break;
			case 1:
				tmp += L"invalid value";
				break;
			default:
				tmp += L"interpretation failure";
				break;
			}
			tmp += L": line " + std::to_wstring(line);
			core::log << tmp;
			exit(1);
		}
	}
}

cfg::logfd::logfd()
:val("kewld.log")
{
	core::cfg.extract[L"logfd"] = this;
}

std::string cfg::logfd::gval()
{
	return val;
}

void cfg::logfd::operator<<(std::wstring input)
{
	std::string tmp(input.begin(), input.end());
	if (input.size() != tmp.size())
		throw 1;
	val = tmp;
}

cfg::usrz_dir::usrz_dir()
:val("usrz/")
{
	core::cfg.extract[L"usrz_dir"] = this;
}

std::string cfg::usrz_dir::gval()
{
	return val;
}

void cfg::usrz_dir::operator<<(std::wstring input)
{
	std::string tmp(input.begin(), input.end());
	if (input.size() != tmp.size())
		throw 1;
	val = tmp;
	if (val[val.size() - 1] != '/')
		val += '/';
}

cfg::port::port()
:val(31337)
{
	core::cfg.extract[L"port"] = this;
}

int cfg::port::gval()
{
	return val;
}

void cfg::port::operator<<(std::wstring input)
{
	int tmp;
	try {
		tmp = std::stoi(input);
	} catch (std::invalid_argument) {
		throw 0;
	}
	if (input != std::to_wstring(tmp))
		throw 0;
	if (tmp <= 0 || tmp > 65535)
		throw 1;
	val = tmp;
}

cfg::clientz::clientz()
:val(8)
{
	core::cfg.extract[L"clientz"] = this;
}

int cfg::clientz::gval()
{
	return val;
}

void cfg::clientz::operator<<(std::wstring input)
{
	int tmp;
	try {
		tmp = std::stoi(input);
	} catch (std::invalid_argument) {
		throw 0;
	}
	if (input != std::to_wstring(tmp))
		throw 0;
	if (tmp <= 0)
		throw 1;
	val = tmp;
}

cfg::passwd::passwd()
:val(core::sha256(L"")), on(false)
{
	core::cfg.extract[L"passwd"] = this;
}

std::wstring cfg::passwd::gval()
{
	return val;
}

bool cfg::passwd::gon()
{
	return on;
}

void cfg::passwd::operator<<(std::wstring input)
{
	if(input.size() > 255 || !core::iz_k(input))
		throw 1;
	std::wstring tmp(core::sha256(input));
	if (tmp != val)
		on = true;
	val = tmp;
}

cfg::attemptz::attemptz()
:val(3)
{
	core::cfg.extract[L"attemptz"] = this;
}

int cfg::attemptz::gval()
{
	return val;
}

void cfg::attemptz::operator<<(std::wstring input)
{
	int tmp;
	try {
		tmp = std::stoi(input);
	} catch (std::invalid_argument) {
		throw 0;
	}
	if (input != std::to_wstring(tmp))
		throw 0;
	if (tmp <= 0)
		throw 1;
	val = tmp;
}

cfg::certfd::certfd()
:val("cert.pem")
{
	core::cfg.extract[L"certfd"] = this;
}

std::string cfg::certfd::gval()
{
	return val;
}

void cfg::certfd::operator<<(std::wstring input)
{
	std::string tmp(input.begin(), input.end());
	if (input.size() != tmp.size())
		throw 1;
	val = std::string(tmp);
	return;
}

cfg::keyfd::keyfd()
:val("key.pem")
{
	core::cfg.extract[L"keyfd"] = this;
}

std::string cfg::keyfd::gval()
{
	return val;
}

void cfg::keyfd::operator<<(std::wstring input)
{
	std::string tmp(input.begin(), input.end());
	if (input.size() != tmp.size())
		throw 1;
	val = tmp;
}


cfg::name::name()
:val(L"kewl-serv")
{
	core::cfg.extract[L"name"] = this;
}

std::wstring cfg::name::gval()
{
	return val;
}

void cfg::name::operator<<(std::wstring input)
{
	if (input.size() > 15 || !iz_k(input))
		throw 1;
	val = input;
}

cfg::hoi_msg::hoi_msg()
:val()
{
	core::cfg.extract[L"hoi_msg"] = this;
}

std::wstring cfg::hoi_msg::gval()
{
	return val;
}

void cfg::hoi_msg::operator<<(std::wstring input)
{
	if (input.size() > 238 || !iz_k(input))
		throw 1;
	val = input;
}

cfg::boi_msg::boi_msg()
:val()
{
	core::cfg.extract[L"boi_msg"] = this;
}

std::wstring cfg::boi_msg::gval()
{
	return val;
}

void cfg::boi_msg::operator<<(std::wstring input)
{
	if (input.size() > 238 || !iz_k(input))
		throw 1;
	val = input;
}

cfg::ded_msg::ded_msg()
:val()
{
	core::cfg.extract[L"ded_msg"] = this;
}

std::wstring cfg::ded_msg::gval()
{
	return val;
}

void cfg::ded_msg::operator<<(std::wstring input)
{
	if (input.size() > 238 || !iz_k(input))
		throw 1;
	val = input;
}

cfg::conn_delay::conn_delay()
:val(500)
{
	core::cfg.extract[L"conn_delay"] = this;
}

int cfg::conn_delay::gval()
{
	return val;
}

void cfg::conn_delay::operator<<(std::wstring input)
{
	int tmp;
	try {
		tmp = std::stoi(input);
	} catch (std::invalid_argument) {
		throw 0;
	}
	if (input != std::to_wstring(tmp))
		throw 0;
	if (tmp < 0)
		throw 1;
	val = tmp;
}

cfg::passwd_invalid_delay::passwd_invalid_delay()
:val(500)
{
	core::cfg.extract[L"passwd_invalid_delay"] = this;
}

int cfg::passwd_invalid_delay::gval()
{
	return val;
}

void cfg::passwd_invalid_delay::operator<<(std::wstring input)
{
	int tmp;
	try {
		tmp = std::stoi(input);
	} catch (std::invalid_argument) {
		throw 0;
	}
	if (input != std::to_wstring(tmp))
		throw 0;
	if (tmp < 0)
		throw 1;
	val = tmp;
}

cfg::flood_delay::flood_delay()
:val(50)
{
	core::cfg.extract[L"flood_delay"] = this;
}

int cfg::flood_delay::gval()
{
	return val;
}

void cfg::flood_delay::operator<<(std::wstring input)
{
	int tmp;
	try {
		tmp = std::stoi(input);
	} catch (std::invalid_argument) {
		throw 0;
	}
	if (input != std::to_wstring(tmp))
		throw 0;
	if (tmp < 0)
		throw 1;
	val = tmp;
}

cfg::flood_msg::flood_msg()
:val(L"w8 m9... ur flooding chat!")
{
	core::cfg.extract[L"flood_msg"] = this;
}

std::wstring cfg::flood_msg::gval()
{
	return val;
}

void cfg::flood_msg::operator<<(std::wstring input)
{
	if (input.size() > 255 || !iz_k(input))
		throw 1;
	val = input;
}

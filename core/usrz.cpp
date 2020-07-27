void usrz::init()
{
	if (chdir(core::cfg.usrz_dir.gval().c_str()) != 0) {
		if (mkdir(core::cfg.usrz_dir.gval().c_str(), 0700) != 0) {
			core::log << L"ERR: cant work with usrz dir";
			exit(EXIT_FAILURE);
		}
	} else if (chdir("..") != 0) {
		core::log << L"ERR: cant change dir to server dir";
		exit(EXIT_FAILURE);
	}
}

uint8_t usrz::registration(std::wstring usr, std::wstring passwd)
{
	{
		std::wifstream test(core::cfg.usrz_dir.gval() + std::string(usr.begin(), usr.end()));
		if (test.is_open()) {
			test.close();
			return 1;
		}
	}
	std::wofstream fd(core::cfg.usrz_dir.gval() + std::string(usr.begin(), usr.end()), std::ofstream::out);
	if (!fd.is_open())
		return -1;
	fd << usr << L' ' << passwd << std::endl;
	fd << L"--- FALZ";
	fd.close();
	return 0;
}

uint8_t usrz::chpasswd(std::wstring usr, std::wstring passwd)
{
	if (passwd.size() != 64)
		return 2;
	std::wfstream fd(core::cfg.usrz_dir.gval() + std::string(usr.begin(), usr.end()), std::ios::in | std::ios::out);
	if (!fd.is_open())
		return 1;
	fd.seekp(std::string(usr.begin(), usr.end()).size() + 1);
	fd << passwd;
	fd.close();
	return 0;
}

uint8_t usrz::chomg(std::wstring usr, wchar_t perm, uint8_t val)
{
	size_t jmp;
	switch (perm) {
	case L'o':
		jmp = 0;
		break;
	case L'm':
		jmp = 1;
		break;
	case L'g':
		jmp = 2;
		break;
	default:
		return 2;
	}
	jmp += std::string(usr.begin(), usr.end()).size() + 66;
	if (val < 0 || val > 2)
		return 3;
	wchar_t da_val = L'-';
	if (val == 1) {
		da_val = perm;
	} else if (val == 2) {
		switch (perm) {
		case L'o':
			da_val = L'O';
			break;
		case L'm':
			da_val = L'M';
			break;
		case L'g':
			da_val = L'G';
			break;
		}
	}
	std::wfstream fd(core::cfg.usrz_dir.gval() + std::string(usr.begin(), usr.end()), std::ios::in | std::ios::out);
	if (!fd.is_open())
		return 1;
	fd.seekp(jmp);
	wchar_t current;
	fd >> current;
	if (current == da_val)
		return -1;
	fd.seekp(jmp);
	fd << da_val;
	fd.close();
	return 0;	
}


usrz::omg::omg()
:val{0, 0, 0}
{
}

usrz::omg::omg(std::wstring da_val)
:val{255, 255, 255}
{
	uint8_t tmp_val[3];
	if (da_val.size() != 3)
		return;
	switch (da_val[0]) {
	case L'-':
		tmp_val[0] = 0;
		break;
	case L'o':
		tmp_val[0] = 1;
		break;
	case L'O':
		tmp_val[0] = 2;
		break;
	default:
		return;
	}

	switch (da_val[1]) {
	case L'-':
		tmp_val[1] = 0;
		break;
	case L'm':
		tmp_val[1] = 1;
		break;
	case L'M':
		tmp_val[1] = 2;
		break;
	default:
		return;
	}

	switch (da_val[2]) {
	case L'-':
		tmp_val[2] = 0;
		break;
	case L'g':
		tmp_val[2] = 1;
		break;
	case L'G':
		tmp_val[2] = 2;
		break;
	default:
		return;
	}

	for (int i = 0; i < 3; i++)
		val[i] = tmp_val[i];
}

bool usrz::omg::iz_k()
{
	return val[0] == 255 ? false : true;
}

uint8_t usrz::omg::go()
{
	return val[0];
}

uint8_t usrz::omg::gm()
{
	return val[1];
}

uint8_t usrz::omg::gg()
{
	return val[2];
}

std::wstring usrz::omg::gv()
{
	std::wstring rtn;
	switch (val[0]) {
	default:
		rtn += L'-';
		break;
	case 1:
		rtn += L'o';
		break;
	case 2:
		rtn += L'O';
	}
	switch (val[1]) {
	default:
		rtn += L'-';
		break;
	case 1:
		rtn += L'm';
		break;
	case 2:
		rtn += L'M';
		break;
	}
	switch (val[2]) {
	default:
		rtn += L'-';
		break;
	case 1:
		rtn += L'g';
		break;
	case 2:
		rtn += L'G';
		break;
	}
	return rtn;
}

void usrz::omg::operator=(usrz::omg permz)
{
	val[0] = permz.go();
	val[1] = permz.gm();
	val[2] = permz.gg();
}

usrz::usr::usr(std::wstring da_usr)
:bypass(false), k(false)
{
	std::string tmp(da_usr.begin(), da_usr.end());
	std::wifstream fd(core::cfg.usrz_dir.gval() + tmp);
	if (!fd.is_open())
		return;
	std::wstring buf;
	int line, tmp1;
	for (line = 1; std::getline(fd, buf); line++) {
		switch (line) { 
		case 1:
			tmp1 = buf.find(32);
			if (tmp1 == std::wstring::npos || tmp1 == 0 || tmp1 == buf.size() - 1)
				return;
			nick = buf.substr(0, tmp1);
			if (nick != da_usr)
				return;
			passwd = buf.substr(tmp1 + 1, buf.size() - tmp1 - 1);
			break;
		case 2:
			if (buf.size() < 7 || buf[3] != 32)
				return;
			omg = core::usrz::omg(buf.substr(0, 3));
			if (!omg.iz_k())
				return;
			buf.erase(0, 4);
			if (buf == L"TRU")
				bypass = true;
			else if (buf == L"FALZ")
				bypass = false;
			else
				return;
			break;
		default:
			return;
		}
	}
	if (line != 3)
		return;
	k = true;
}

bool usrz::usr::iz_k()
{
	return k;
}

bool usrz::usr::auth(std::wstring da_passwd)
{
	if (k && da_passwd == passwd)
		return true;
	usleep(1000 * core::cfg.passwd_incorrect_delay.gval());
	return false;
}

bool usrz::usr::gbypass()
{
	return bypass;
}

void usrz::usr::operator=(usr da_usr)
{
	nick = da_usr.nick;
	passwd = da_usr.passwd;
	k = da_usr.k;
	omg = da_usr.omg;
}

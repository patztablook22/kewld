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

usrz::usr::usr(std::wstring da_usr)
:k(false)
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
			passwd = buf.substr(tmp1 + 1, buf.size() - tmp1 - 1);
			break;
		default:
			return;
		}
	}
	k = true;
}

bool usrz::usr::iz_k()
{
	return k;
}

bool usrz::usr::auth(std::wstring da_passwd)
{
	return k && da_passwd == passwd;
}

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

void usrz::omg::operator=(usrz::omg permz)
{
	val[0] = permz.go();
	val[1] = permz.gm();
	val[2] = permz.gg();
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
			if (nick != da_usr)
				return;
			passwd = buf.substr(tmp1 + 1, buf.size() - tmp1 - 1);
			break;
		case 2:
			permz = core::usrz::omg(buf);
			if (!permz.iz_k())
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
	return k && da_passwd == passwd;
}

std::wstring exec::escape(std::wstring input)
{
	std::wstring res;
	bool par = false;
	for (int i = 0; i < input.size(); i++) {
		wint_t ch = input[i];
		switch (ch) {
		case L'"':
			res += L"\\\"";
			break;
		case L'\\':
			res += L"\\\\";
			break;
		case L'/':
			res += L"\\/";
			break;
		case 32:
			res += L' ';
			par = true;
			break;
		default:
			res += ch;
			break;
		}
	}
	return par ? L'"' + res + L'"' : res;
}

size_t exec::interpreter(std::wstring input, std::vector<std::wstring> &trg, size_t end)
{
	bool in = false, par = false;
	int iter = 0;
	std::wstring tmp;
	while (iter < input.size()) {
		wint_t ch = input[iter++];
		switch (ch) {
		case L'\\':
			if (iter == input.size())
				break;
			switch (input[iter++]) {
			case L'\\':
				tmp += L'\\';
				break;
			case L'"':
				tmp += L'"';
				break;
			case L'\'':
				tmp += L'\'';
				break;
			case L'/':
				tmp += L'/';
				break;
			default:
				break;
			}
			break;
		case L'"':
			switch (in) {
			case true:
				if (iter < input.size() && input[iter++] != 32)
					return (end == -1 ? iter - 1 : -1);
				trg.push_back(tmp);
				if (iter > end)
					return iter;
				tmp.clear();
				in = false;
				break;
			case false:
				if (iter > 1 && input[iter - 2] != 32)
					return (end == -1 ? iter - 1 : -1);
				in = true;
			}	
			break;
		case L' ':
			switch (in) {
			case true:
				if (tmp.size() == 0 || tmp[tmp.size() - 1] != L' ')
					tmp += L' ';
				break;
			case false:
				if (tmp.size() != 0) {
					trg.push_back(tmp);
					if (iter > end)
						return iter;
					tmp.clear();
				}
				break;
			}
			break;
		default:
			tmp += ch;
		}
	}
	if (tmp.size() != 0 || in)
		trg.push_back(tmp);
	if (in)
		return iter + 1;
	return iter;
}

void exec::operator<<(std::wstring input)
{
	std::vector<std::wstring> arg;
	core::serv::handler *diz = core::serv.nexus.diz_handler();
	if (!diz->gready())
		return;
	if (core::exec.interpreter(input, arg) != input.size()) {
		*diz << core::serv::msg(L"serv", L"ERR: interpretation failed");
		return;
	}
	if (arg.size() == 0)
		return;
	if (cmdz.find(arg[0]) == cmdz.end()) {
		*diz << core::serv::msg(L"serv", L"ERR: command not found: \"" + arg[0] + L'"');
		return;
	}

	switch (cmdz[arg[0]]->do_it(arg)) {
	case 0:
		break;
	case 2:
		*diz << core::serv::msg(L"serv", L"ERR: invalid input");
		break;
	case 3:
		*diz << core::serv::msg(L"serv", L"ERR: im sorry " + diz->gusr() + L", im afraid i cant do dat");
	default:
		break;
	}
}

void exec::add(std::wstring name, cmd *ptr)
{
	if (name.size() < 2 || name.size() > 15 || name.find_first_of(L" _/") != std::wstring::npos)
		return;
	if (cmdz.find(name) != cmdz.end())
		return;
	cmdz[name] = ptr;
}

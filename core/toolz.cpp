bool iz_k(wint_t chk)
{
	if ( \
		(chk >= 32 && chk <= 176) /* standard ASCII without da weird mess at beginning*/ || \
		(chk >= 192 && chk != 215 && chk != 247 && chk <= 591) /* some čžech crap */ || \
		(chk >= 1025 && chk <= 1105) /* cука блять etc. xd */ \
		)
		return true;
	return false;
}

bool iz_k(std::wstring chk)
{
	for (int i = 0; i < chk.size(); i++)
		if(!iz_k(chk[i]))
			return false;
	return true;
}

std::wstring trim(std::wstring s)
{
	size_t i, done = 0;
	while ((i = s.find(32, done)) != std::wstring::npos) {
		if (i == 0 || i == s.size() - 1 || s[i - 1] == 32 || s[i + 1] == 32)
			s.erase(i, 1);
		else
			done++;
	}
	return s;
}

std::wstring ver_echo(int v)
{
	std::wstring w[3];
	for (int j = 2; j > 0; j--) {
		w[j] = std::to_wstring(v % 10);
		v /= 10;
	}
	w[0] = std::to_wstring(v);
	return std::wstring(L"v") + w[0] + std::wstring(L".") + w[1] + std::wstring(L".") + w[2];
}

void quit(int)
{
	std::wcout << L"\nshutting down..." << std::endl;
	exit(EXIT_SUCCESS);
}

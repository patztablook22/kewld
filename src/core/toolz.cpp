bool iz_k(wint_t chk)
{
	if ( \
		(chk >= 32 && chk <= 591) /* ASCII etc. */ || \
		(chk >= 1025 && chk <= 1105) /* cука блять etc. xd */ || \
		(chk >= 9472 && chk <= 9679) /* box-drawing charz etc. */ \
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
	core::log << L"shutting down...";
	exit(EXIT_SUCCESS);
}

void daemonize()
{
	pid_t pid = fork();
	if (pid < 0) {
		core::log << L"ERR: forking failed";
		exit(EXIT_FAILURE);
	}

	if (pid > 0) {
		core::log << L"starting daemon";
		core::log.close();
		exit(EXIT_SUCCESS);
	}
	
	if (setsid() < 0) {
		core::log << L"SID set failed";
		exit(EXIT_FAILURE);
	}

	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	core::log.psss();

	pid = fork();
	if (pid < 0) {
		core::log << L"ERR: forking failed";
		exit(EXIT_FAILURE);
	}
	if (pid > 0) {
		core::log << L"daemon started (PID = " + std::to_wstring(pid) + L')';
		core::log.close();
		exit(EXIT_SUCCESS);
	}
}

std::wstring sha256(std::wstring input)
{
	std::string tmp(input.begin(), input.end());
	const char *string = tmp.c_str();
	char outputBuffer[65];
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, string, strlen(string));
	SHA256_Final(hash, &sha256);
	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
	}
	outputBuffer[64] = 0;
	tmp = outputBuffer;
	return std::wstring(tmp.begin(), tmp.end());
}

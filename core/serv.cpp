serv::serv()
:servsock(0)
{
}

serv::~serv()
{
	if (servsock != 0)
		close(servsock);
}

void serv::init()
{
	SSL_library_init();
	int port = core::cfg.port.gval();
	int clientz = core::cfg.clientz.gval();
	ctx = init_ctx();
	load_certificatez(core::cfg.certfd.gval().c_str(), core::cfg.keyfd.gval().c_str());
	servsock = serve(core::cfg.port.gval(), core::cfg.clientz.gval());
}

void serv::listener()
{
	for (;;) {
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);
		SSL *ssl;
		int client = accept(servsock, (struct sockaddr *)&addr, &len);
		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);
		new handler(ssl);
	}
}

serv::msg::msg()
:valid(false)
{
}

serv::msg::msg(std::wstring input)
:valid(false)
{
	int pos = input.find(32);
	if (pos == std::wstring::npos || pos == 0 || pos == input.size() - 1)
		return;
	usr = core::trim(input.substr(0, pos));
	body = core::trim(input.substr(pos + 1, input.size() - pos - 1));
	if (usr.size() < 3 || usr.size() > 15 || body.size() == 0 || body.size() > 255 || !core::iz_k(usr) || !core::iz_k(body))
		return;
	if (body[0] == '@') {
		pos = body.find(32);
		if (pos == std::wstring::npos)
			pos = body.size();
		trg = body.substr(1, pos - 1);
	}

	valid = true;
}

serv::msg::msg(std::wstring da_usr, std::wstring da_body)
:valid(false)
{
	if (da_usr.size() < 3 || da_usr.size() > 15 || da_body.size() == 0 || da_body.size() > 255 || !core::iz_k(da_usr) || !core::iz_k(da_body))
		return;
	usr = da_usr;
	body = da_body;
	valid = true;
}

std::wstring serv::msg::gusr()
{
	return usr;
}

std::wstring serv::msg::gbody()
{
	return body;
}

std::wstring serv::msg::gtrg()
{
	return trg;
}

bool serv::msg::gvalid()
{
	return valid;
}

void serv::msg::operator=(msg da_msg)
{
	usr = da_msg.gusr();
	body = da_msg.gbody();
	trg = da_msg.gtrg();
	valid = da_msg.gvalid();
}

serv::handler::handler(SSL *da_ssl)
:ready(false)
{
	ssl = da_ssl;
	std::thread sniff_th(&core::serv::handler::sniffer, this);
	sniff_th.detach();
}

serv::handler::~handler()
{
	if (core::serv.nexus.leave(this) == 0 && ready) {
		core::serv.nexus << core::serv::msg(L"serv", L"/usrz disconn " + usr);
		std::wcout << usr + L" disconnected" << std::endl;
	}
	int sockfd = SSL_get_fd(ssl);
	SSL_free(ssl);
	close(sockfd);
}

bool serv::handler::gready()
{
	return ready;
}

void serv::handler::imma_ready()
{
	ready = true;
	core::serv.nexus << core::serv::msg(L"serv", L"/usrz conn " + usr);
	std::wcout << usr + L" connected" << std::endl;
}


void serv::handler::sniffer()
{
	try {
		int sockfd = SSL_get_fd(ssl);
		if (SSL_accept(ssl) == -1 ) {
			ERR_print_errors_fp(stderr);
			delete this;
			return;
		}
	
		int buf0;
		std::wstring buf1;
		*this >> buf0;
		usleep(1000 * core::cfg.conn_delay.gval());
		if (buf0 != VERSION) {
			buf1 = core::ver_echo(VERSION);
			*this << buf1;
			delete this;
			return;
		}
		if (core::cfg.passwd.gval().size() != 0) {
			for (int i = 1;; i++) {
				*this << L"passwd";
				*this >> buf1;
				if (buf1 == core::cfg.passwd.gval())
					break;
				usleep(1000 * core::cfg.passwd_invalid_delay.gval());
				if (i == core::cfg.attemptz.gval()) {
					*this << L"attemptz";
					delete this;
					return;
				}
			}
		}
		*this << L"succeed";
		*this >> buf1;
		switch (core::serv.nexus.join(buf1, this)) {
		case 0:
			usr = buf1;
			*this << L"k" + usr;
			break;
		case 1:
			*this << L"f";
			delete this;
			return;
		case 2:
			*this << L"n";
			delete this;
			return;
		default:
			delete this;
			return;
		}
		*this >> buf1;
		if (buf1 != L"ready") {
			delete this;
			return;
		}

		std::vector<std::wstring> usrz;
		core::serv.nexus.connno(usrz);
		buf1.clear();

		for (int i = 0; i < usrz.size(); i++) {
			if (usrz[i] == usr) {
				usrz.erase(usrz.begin() + i);
				i--;
				continue;
			}
			if (buf1.size() + usrz[i].size() > 255) {
				*this << buf1;
				std::wcout << L'|' << buf1 << L'|' << std::endl;
				*this >> buf1;
				buf1.clear();
			} else if (buf1.size() != 0) {
				buf1 += 32;
			}
			buf1 += usrz[i];			
		}
		buf1 += L',';
		*this << buf1;
		*this >> buf1;

		*this << std::to_wstring(core::cfg.clientz.gval()) + L'|' + core::cfg.name.gval();
		*this >> buf1;

		*this << L'|' + core::cfg.hoi_msg.gval();
		*this >> buf1;
		*this << L'|' + core::cfg.boi_msg.gval();

		*this >> buf1;

		if (buf1 != L"sniffing") {
			delete this;
			return;
		}
		core::serv::msg buf2;
		timeval tm, tmp;
		gettimeofday(&tm, NULL);
		tm.tv_sec -= core::cfg.flood_delay.gval() / 1000 + 1;
		imma_ready();
		for (;;) {
			*this >> buf2;
			if (buf2.gbody()[0] == L'/' && buf2.gusr() == L"kewl") {
				*this << core::serv::msg(L"serv", buf2.gbody());
			} else {
				gettimeofday(&tmp, NULL);
				if (1000000 * (tmp.tv_sec - tm.tv_sec) + tmp.tv_usec - tm.tv_usec >= 1000 * core::cfg.flood_delay.gval())
					core::serv.nexus << buf2;
				else
					*this << core::serv::msg(L"serv", L"w8 m9... ur flooding chat!");
				tm = tmp;
			}
		}
		
		delete this;
	} catch (...) {
		delete this;
	}
}

void serv::handler::operator<<(std::wstring todo)
{
	if (!core::iz_k(todo))
		return;
	if (ssl == NULL)
		throw 1;
	if (SSL_write(ssl, todo.c_str(), 4 * todo.size()) <= 0)
		throw 1;
}

void serv::handler::operator<<(msg todo)
{
	if (!todo.gvalid())
		return;
	*this << todo.gusr() + L' ' + todo.gbody();
}

void serv::handler::operator<<(int todo)
{
	if (ssl <= 0)
		throw 1;
	int32_t buf = todo;
	if (SSL_write(ssl, &buf, sizeof(buf)) <= 0)
		throw 1;
}

std::wstring serv::handler::gusr()
{
	return usr;
}

void serv::handler::operator>>(int &trg)
{
	if (ssl == NULL)
		throw 1;
	int32_t buf;
	if (SSL_read(ssl, &buf, sizeof(buf)) <= 0)
		throw 1;
	trg = buf;
}

void serv::handler::operator>>(std::wstring &trg)
{
	if (ssl == NULL)
		throw 1;
	wchar_t buf[1024];
	int bytez = SSL_read(ssl, &buf, sizeof(buf));
	if (bytez <= 0)
		throw 1;
	buf[bytez / 4] = 0;
	trg = buf;
}

void serv::handler::operator>>(core::serv::msg &trg)
{
	std::wstring buf;

	*this >> buf;
	trg = core::serv::msg(buf);
}

serv::nexus::~nexus()
{
	*this << core::serv::msg(L"serv", L"/disconn");
}

void serv::nexus::operator<<(msg da_msg)
{
	if (!da_msg.gvalid())
		return;
	if (da_msg.gusr() != L"serv" && (connected.find(da_msg.gusr()) == connected.end() || !connected[da_msg.gusr()]->gready()))
		return;
	if (da_msg.gtrg().size() == 0) {
		for (const std::pair<std::wstring, handler *> key: connected)
			if (key.second->gready())
				*key.second << da_msg;
	} else {
		if (connected.find(da_msg.gtrg()) != connected.end()) {
			if (connected[da_msg.gtrg()]->gready())
				*connected[da_msg.gtrg()] << da_msg;
			if (da_msg.gusr() != da_msg.gtrg())
				*connected[da_msg.gusr()] << da_msg;
		} else {
			*connected[da_msg.gusr()] << core::serv::msg(L"serv", L"ERR: \"" + da_msg.gtrg() + L"\" iz not online");
		}

	}
}

int serv::nexus::join(std::wstring &usr, handler *da_handler)
{
	if (connected.size() == core::cfg.clientz.gval())
		return 1;
	int pos;
	for (int i = 0; pos = usr.find(','); i++) {
		if (pos == std::wstring::npos) {
			pos = usr.size();
			i = 15;
		}
		if (pos > 15 || pos < 3 || !core::iz_k(usr.substr(0, pos)) || usr.substr(0, pos) == L"kewl" || usr.substr(0, pos) == L"serv")
			return 3;
		if (connected.find(usr.substr(0, pos)) == connected.end())
			break;
		usr.erase(0, pos + 1);
		if (i == 15)
			return 2;
	}
	if ((pos = usr.find(',')) != std::wstring::npos)
		usr.erase(pos, usr.size() - pos);
	if (usr.find(32) != std::wstring::npos || usr.find(10) != std::wstring::npos)
		return 3;
	if (connected.size() == core::cfg.clientz.gval())
		return 1;
	connected[usr] = da_handler;
	return 0;
}

int serv::nexus::leave(handler *da_handler)
{
	if (connected.find(da_handler->gusr()) == connected.end())
		return 1;
	connected.erase(da_handler->gusr());
	return 0;
}

int serv::nexus::connno()
{
	return connected.size();
}

int serv::nexus::connno(std::vector<std::wstring> &trg)
{
	trg.clear();
	for (const std::pair<std::wstring, handler *> key: connected)
		trg.push_back(key.first);
	return connected.size();
}

int serv::serve(int port, int clientz)
{
	int sockfd, bacclog = clientz * 1.1, tmp = 1;
	if (bacclog == clientz)
		bacclog++;
	struct sockaddr_in addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		std::cerr << "ERR: bind failed\n";
		exit(1);
	}

	if (listen(sockfd, bacclog) != 0) {
		std::cerr << "ERR: listen failed\n";
		exit(1);
	}

	std::wcout << L"serving on port " << port << L" ...YAY!\n";
	std::wcout << L"----------------------------" << std::endl;
	return sockfd;
}

SSL_CTX* serv::init_ctx()
{
	const SSL_METHOD *mth;
	SSL_CTX *tmp;
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	mth = SSLv23_method();
	tmp = SSL_CTX_new(mth);
	if (tmp == NULL)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return tmp;
}

void serv::load_certificatez(const char *certfd, const char *keyfd)
{
	if (SSL_CTX_use_certificate_file(ctx, certfd, SSL_FILETYPE_PEM) <= 0) {
		std::cerr << "ERR: unable to read cert file: " << certfd << '\n';
		exit(1);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, keyfd, SSL_FILETYPE_PEM) <= 0) {
		std::cerr << "ERR: unable to read key file: " << keyfd << '\n';
		exit(1);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		std::cerr << "ERR: private key doesnt match the public certificate\n";
		exit(1);
	}
}


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

std::thread::id serv::handler::gtid()
{
	return tid;
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
:ready(false), permz(L"---"), disconn_t(-1)
{
	ssl = da_ssl;
	std::thread sniff_th(&core::serv::handler::sniffer, this);
	sniff_th.detach();
}

serv::handler::~handler()
{
	core::serv.nexus.leave(this);
	if (ssl == NULL)
		return;
	int sockfd = SSL_get_fd(ssl);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(sockfd);
}

bool serv::handler::gready()
{
	return ready;
}
uint8_t serv::handler::gdisconn_t()
{
	return disconn_t;
}

uint8_t serv::handler::kick()
{
	if (!ready)
		return 1;
	disconn_t = 1;
	*this << core::serv::msg(L"serv", L"/disconn k");
	core::serv.nexus.leave(this);
	int sockfd = SSL_get_fd(ssl);
	SSL_shutdown(ssl);
	close(sockfd);
	return 0;
}

void serv::handler::imma_ready()
{
	ready = true;
	core::serv.nexus << core::serv::msg(L"serv", L"/usrz conn " + usr);
	core::log << usr + L" connected";
}


void serv::handler::sniffer()
{
	tid = std::this_thread::get_id();
	try {
		int sockfd = SSL_get_fd(ssl);
		if (SSL_accept(ssl) == -1 ) {
			ERR_print_errors_fp(stderr);
			delete this;
			return;
		}
	
		int buf0;
		std::wstring buf1, stg;
		*this >> buf0;
		usleep(1000 * core::cfg.conn_delay.gval());
		if (buf0 != VERSION) {
			buf1 = core::ver_echo(VERSION);
			*this << buf1;
			delete this;
			return;
		}
		*this << L"kk";
		*this >> stg;
		if (stg.size() < 3 || stg.size() > 15 || !iz_k(stg) || stg.find_first_of(L" /") != std::wstring::npos || stg == L"kewl" || stg == L"serv") {
			delete this;
			return;
		}
		core::usrz::usr usrdata(stg);
		if (core::cfg.passwd.gon() || usrdata.iz_k()) {
			for (int i = 1;; i++) {
				*this << L"passwd " + std::wstring((usrdata.iz_k() ? L"usr" : L"serv"));
				*this >> buf1;
				buf1.erase(0, 1);
				if (usrdata.auth(buf1))
					break;
				if (buf1 == core::cfg.passwd.gval()) {
					if (usrdata.iz_k()) {
						*this << L"registered";
						delete this;
						return;
					}
					break;
				}
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

		switch (core::serv.nexus.join(stg, this)) {
		case 0:
			usr = stg;
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
				*this >> buf1;
				buf1.clear();
			} else if (buf1.size() != 0) {
				buf1 += 32;
			}
			buf1 += usrz[i];			
		}
		buf1 += L' ';
		*this << buf1;
		*this >> buf1;

		*this << std::to_wstring(core::cfg.clientz.gval()) + L'|' + core::cfg.name.gval();
		*this >> buf1;

		if (buf1 != L"sniffing") {
			delete this;
			return;
		}
		core::serv::msg buf2;
		timeval tm, tmp;
		gettimeofday(&tm, NULL);
		tm.tv_sec -= core::cfg.flood_delay.gval() / 1000 + 1;
		if (usrdata.permz.iz_k())
			permz = usrdata.permz;
		if (core::cfg.hoi_msg.gval().size() != 0)
			*this << core::serv::msg(L"serv", L'@' + usr + L' ' + core::cfg.hoi_msg.gval());
		imma_ready();
		for (;;) {
			*this >> buf2;
			if (buf2.gbody()[0] == L'/') {
				int pos = buf2.gbody().find(32);
				if (pos == std::wstring::npos)
					pos = buf2.gbody().size();
				std::wstring tmp1 = buf2.gbody().substr(1, pos - 1);
				if (tmp1 == L"servctl") {
					if (buf2.gbody().size() <= 9)
						continue;
					core::exec <<  buf2.gbody().substr(9, buf2.gbody().size() - 9);
				} else if (tmp1 == L"disconn") {
					*this << core::serv::msg(L"serv", L"/disconn d " + core::exec.escape(core::cfg.boi_msg.gval()));
					disconn_t = 0;
				} else {
					*this << core::serv::msg(L"serv", buf2.gbody());
				}
			} else {
				gettimeofday(&tmp, NULL);
				if (1000000 * (tmp.tv_sec - tm.tv_sec) + tmp.tv_usec - tm.tv_usec >= 1000 * core::cfg.flood_delay.gval())
					core::serv.nexus << buf2;
				else
					*this << core::serv::msg(L"serv", core::cfg.flood_msg.gval());
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
	*this << core::serv::msg(L"serv", L"/disconn s " + core::exec.escape(core::cfg.ded_msg.gval()));
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

int serv::nexus::join(std::wstring &da_usr, handler *da_handler)
{
	if (connected.size() == core::cfg.clientz.gval())
		return 1;
	if (connected.find(da_usr) != connected.end())
		return 2;
	if (connected.size() == core::cfg.clientz.gval())
		return 1;
	connected[da_usr] = da_handler;
	threadz[da_handler->gtid()] = da_handler;
	return 0;
}

int serv::nexus::leave(handler *da_handler)
{
	if (connected.find(da_handler->gusr()) == connected.end())
		return 1;
	if (threadz.find(da_handler->gtid()) != threadz.end())
		threadz.erase(da_handler->gtid());
	connected.erase(da_handler->gusr());
	if (da_handler->gready()) {
		switch (da_handler->gdisconn_t()) {
		default:
		case 255:
			*this << core::serv::msg(L"serv", L"/usrz lost " + da_handler->gusr());
			core::log << L"connection with " + da_handler->gusr() + L" lost";
			break;
		case 0:
			*this << core::serv::msg(L"serv", L"/usrz disconn " + da_handler->gusr());
			core::log << da_handler->gusr() + L" disconnected";
			break;
		case 1:
			*this << core::serv::msg(L"serv", L"/usrz kick " + da_handler->gusr());
			core::log << da_handler->gusr() + L" kicked out";
			break;
		}
	}
	return 0;
}

int serv::nexus::kick(std::wstring nick)
{
	if (connected.find(nick) == connected.end())
		return 1;
	if (connected[nick]->kick() != 0)
		return 2;
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

serv::handler *serv::nexus::diz_handler()
{
	if (threadz.find(std::this_thread::get_id()) == threadz.end())
		return NULL;
	return threadz[std::this_thread::get_id()];
}

core::usrz::omg serv::nexus::client_omg(std::wstring nick)
{
	if (connected.find(nick) == connected.end())
		return core::usrz::omg(L"---");
	return connected[nick]->permz;
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
		core::log << L"ERR: bind failed";
		exit(1);
	}

	if (listen(sockfd, bacclog) != 0) {
		core::log << L"ERR: listen failed";
		exit(1);
	}

	core::log << L"serving on port " + std::to_wstring(port);
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
		core::log << L"ERR: unable to read SSL cert file";
		exit(1);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, keyfd, SSL_FILETYPE_PEM) <= 0) {
		core::log << L"ERR: unable to read SSL key file";
		exit(1);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		core::log << L"ERR: private key doesnt match the public certificate";
		exit(1);
	}
}


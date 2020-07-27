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
	if (pos == std::wstring::npos || pos == 0 || pos == input.size() - 1 || !core::iz_k(input))
		return;
	usr = input.substr(0, pos);
	std::wstring tmp = input.substr(pos + 1, input.size() - pos - 1);
	wint_t last = 32;
	for (int i = 0; i < tmp.size(); i++) {
		wint_t ch = tmp[i];
		switch (ch) {
		case L'\\':
			i++;
			switch (tmp[i]) {
			case L'\\':
				body += L"\\\\";
				last = L'\\';
				break;
			case L'"':
				body += L"\\\"";
				last = L'"';
				break;
			}
			break;
		case 32:
			if (last == 32)
				break;
		default:
			body += ch;
			last = ch;
			break;
		}
	}
	if (body.size() == 0 || body.size() > 255)
		return;
	if (body[0] == L'@') {
		pos = body.find(32);
		if (pos == -1)
			pos = body.size();
		trg = body.substr(1, pos - 1);
	}
	valid = true;
}

serv::msg::msg(std::wstring da_usr, std::wstring da_body)
:valid(false)
{
	if ((da_usr.size() < 3 || da_usr.size() > 15 || da_body.size() == 0 || da_body.size() > 255 || !core::iz_k(da_usr) || !core::iz_k(da_body)) && !(da_usr == L"hr" && da_body.size() == 0))
		return;
	usr = da_usr;
	body = da_body;
	if (body[0] == '@') {
		int pos = body.find(32);
		if (pos == std::wstring::npos)
			pos = body.size();
		trg = body.substr(1, pos - 1);
	}
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
:ready(false), disconn_t(-1)
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

timeval serv::handler::glast()
{
	return last;
}

void serv::handler::imma_ready()
{
	ready = true;
	if (core::cfg.hoi_msg.gval().size() != 0)
		*this << core::serv::msg(L"serv", L'@' + usr + L' ' + core::cfg.hoi_msg.gval());
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
		if (stg.size() < 3 || stg.size() > 15 || !iz_k(stg) || stg.find_first_of(L" /\\") != std::wstring::npos || stg == L"kewl" || stg == L"serv") {
			delete this;
			return;
		}
		usrdata = new core::usrz::usr(stg);
		if (core::cfg.passwd.gon() || usrdata->iz_k()) {
			for (int i = 1;; i++) {
				*this << L"passwd " + std::wstring((usrdata->iz_k() ? L"usr" : L"serv"));
				*this >> buf1;
				buf1.erase(0, 1);
				if (usrdata->auth(buf1))
					break;
				if (buf1 == core::cfg.passwd.gval()) {
					if (usrdata->iz_k()) {
						*this << L"registered";
						delete this;
						return;
					}
					break;
				}
				if (!usrdata->iz_k())
					usleep(1000 * core::cfg.passwd_incorrect_delay.gval());
				if (i == core::cfg.attemptz.gval()) {
					*this << L"attemptz";
					delete this;
					return;
				}
			}
		}
		{
			timeval timeout = core::cfg.drop_timeout.gval();
			if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
				delete this;
				return;
			}
			if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
				delete this;
				return;
			}
		}
		*this << L"succeed";
		*this >> buf1;

		switch (core::serv.nexus.join(stg, this)) {
		case 0:
			usr = stg;
			*this << L"k" + usrdata->omg.gv() + usr;
			break;
		case 1:
			*this << L"f";
			delete this;
			return;
		case 2:
			*this << L"n";
			delete this;
			return;
		case 3:
			*this << L"r";
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

		*this << std::to_wstring(core::cfg.drop_timeout.gval().tv_sec);
		*this >> buf1;

		if (buf1 != L"sniffing") {
			delete this;
			return;
		}
		core::serv::msg buf2;
		timeval tmp;
		gettimeofday(&last, NULL);
		last.tv_sec -= core::cfg.flood_delay.gval() / 1000 + 1;

		imma_ready();
		for (;;) {
			*this >> buf2;
			if (buf2.gbody()[0] == L'/') {
				if (buf2.gbody().size() == 1)
					continue;
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
				} else if (tmp1 == L"whoiz") {
					if (buf2.gbody().size() < 12 || buf2.gbody().size() > 24)
						continue;
					tmp1 = buf2.gbody().substr(8, buf2.gbody().size() - 9);
					if (!core::serv.nexus.gready(tmp1)) {
						*this << core::serv::msg(L"serv", L"ERR: no such usr: \"" + tmp1 + L'"');
						continue;
					}
					*this << core::serv::msg(L"hr", L"");
					*this << core::serv::msg(L"serv", L"    nicc | \\1" + tmp1);
					*this << core::serv::msg(L"serv", L"last msg | \\1" + core::serv.nexus.glast(tmp1));

					*this << core::serv::msg(L"serv", L"     omg | \\1" + core::serv.nexus.gusrdata(tmp1).omg.gv());
					if (core::serv.nexus.gusrdata(tmp1).gbypass())
						*this << core::serv::msg(L"serv", L"  bypass | \\1TRU");
					else
						*this << core::serv::msg(L"serv", L"  bypass | \\1FALZ");
					*this << core::serv::msg(L"hr", L"");
				} else if (tmp1 == L"register") {
					if (usrdata->iz_k()) {
						*this << core::serv::msg(L"serv", L"ERR: ur already registered here");
						continue;
					}
					if (!core::cfg.allow_registration.gval()) {
						*this << core::serv::msg(L"serv", L"ERR: registration iz not allowed here");
						continue;
					}
					std::wstring buf0, buf1;
					*this << core::serv::msg(L"serv", L"/usrz register 0");
					*this >> buf0;
					*this << core::serv::msg(L"serv", L"/usrz register 1");
					*this >> buf1;
					if (buf0 != buf1) {
						*this << core::serv::msg(L"serv", L"ERR: passwdz dont match");
						continue;
					}
					buf0.erase(0, 1);
					if (core::usrz.registration(usr, buf0) != 0) {
						*this << core::serv::msg(L"serv", L"ERR: problem with creating usr file");
						continue;
					}
					usrdata = new core::usrz::usr(usr);
					core::log << L"registration successful: " + usr;
					*this << core::serv::msg(L"serv", L"registration successful");
				} else if (tmp1 == L"omg_f5") {
					core::usrz::usr tmpud(usr);
					usrdata->omg = tmpud.omg;
				} else if (tmp1 == L"chpasswd") {
					if (!usrdata->iz_k()) {
						*this << core::serv::msg(L"serv", L"ERR: ur not registered here");
						continue;
					}
					std::wstring buf0, buf1, buf2;
					*this << core::serv::msg(L"serv", L"/usrz chpasswd 0");
					*this >> buf0;
					if (!usrdata->auth(buf0.substr(1, buf0.size() - 1))) {
						*this << core::serv::msg(L"serv", L"ERR: passwd incorrect");
						continue;
					}
					*this << core::serv::msg(L"serv", L"/usrz chpasswd 1");
					*this >> buf1;
					*this << core::serv::msg(L"serv", L"/usrz chpasswd 2");
					*this >> buf2;
					if (buf1 != buf2) {
						*this << core::serv::msg(L"serv", L"ERR: passwdz dont match");
						continue;
					}
					if (buf0 == buf1) {
						*this << core::serv::msg(L"serv", L"WARN: same as current value");
						continue;
					}
					buf1.erase(0, 1);
					if (core::usrz.chpasswd(usr, buf1) != 0) {
						*this << core::serv::msg(L"serv", L"ERR: problem with editing usr file");
						continue;
					}
					*this << core::serv::msg(L"serv", L"passwd change successful");
				} else {
					*this << core::serv::msg(L"serv", buf2.gbody());
				}
			} else {
				gettimeofday(&tmp, NULL);
				int s = tmp.tv_sec - last.tv_sec;
				bool elapsed;
				if (s < core::cfg.flood_delay.gval() / 1000)
					elapsed = false;
				else if (s > core::cfg.flood_delay.gval() / 1000 + 1)
					elapsed = true;
				else if (1000 * s + (tmp.tv_usec - last.tv_usec) / 1000 >= core::cfg.flood_delay.gval())
					elapsed = true;
				else
					elapsed = false;

				if (elapsed)
					core::serv.nexus << buf2;
				else
					*this << core::serv::msg(L"serv", core::cfg.flood_msg.gval());
				last = tmp;
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
	trg.clear();
	if (ssl == NULL)
		throw 1;
	std::wstring tmp;
	int bytez;
	do {
		wchar_t buf[1024];
		bytez = SSL_read(ssl, &buf, sizeof(buf));
		if (bytez <= 0) {
			if (errno == EAGAIN)
				disconn_t = 2;
			throw 1;
		}
		buf[bytez / 4] = 0;
		tmp = buf;
	} while (tmp == L"/" && gready());
	trg = tmp;
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
		if (da_msg.gtrg().size() > 15 || da_msg.gtrg().size() < 3) {
			if (da_msg.gusr() != L"serv")
				*connected[da_msg.gusr()] << core::serv::msg(L"serv", L"ERR: nicc size must be between 3 and 15 charz");
			return;
		}
		if (connected.find(da_msg.gtrg()) != connected.end()) {
			if (connected[da_msg.gtrg()]->gready())
				*connected[da_msg.gtrg()] << da_msg;
			if (da_msg.gusr() != da_msg.gtrg() && da_msg.gusr() != L"serv")
				*connected[da_msg.gusr()] << da_msg;
		} else if (da_msg.gusr() != L"serv") {
			*connected[da_msg.gusr()] << core::serv::msg(L"serv", L"ERR: \"" + da_msg.gtrg() + L"\" iz not online");
		}

	}
}

bool serv::nexus::gready(std::wstring nicc)
{
	if (connected.find(nicc) != connected.end() && connected[nicc]->gready())
		return true;
	return false;
}

int serv::nexus::join(std::wstring &da_usr, handler *da_handler)
{
	if (!da_handler->usrdata->iz_k() && core::cfg.registered_only.gval())
		return 3;
	if (connected.size() >= core::cfg.clientz.gval() && !da_handler->usrdata->gbypass())
		return 1;
	if (connected.find(da_usr) != connected.end())
		return 2;
	if (connected.size() >= core::cfg.clientz.gval() && !da_handler->usrdata->gbypass())
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
		case 2:
			*this << core::serv::msg(L"serv", L"/usrz timeo " + da_handler->gusr());
			core::log << da_handler->gusr() + L" timed out";
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

core::usrz::usr serv::nexus::gusrdata(std::wstring nicc)
{
	if (!gready(nicc))
		return core::usrz::usr(L"");
	return *connected[nicc]->usrdata;
}

std::wstring serv::nexus::glast(std::wstring nicc)
{
	if (!gready(nicc))
		return L"";
	timeval last = connected[nicc]->glast(), tmp;
	gettimeofday(&tmp, NULL);
	unsigned long long int diff = tmp.tv_sec - last.tv_sec;
	if (diff <= 1)
		return L"now";
	std::wstring res(std::to_wstring(diff % 60) + L's');
	diff /= 60;
	if (diff == 0)
		goto da_return;
	res.insert(0, std::to_wstring(diff % 60) + L"m ");
	diff /= 60;
	if (diff == 0)
		goto da_return;
	res.insert(0, std::to_wstring(diff) + L"h ");
	da_return:
	res.insert(0, L"now - ");
	return res;	
}

int serv::serve(int port, int clientz)
{
	int sockfd, bacclog = clientz * 1.1, tmp = 1;
	if (bacclog == clientz)
		bacclog++;
	struct sockaddr_in addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp)) < 0) {
		core::log << L"ERR: setsockopt failed";
		exit(EXIT_FAILURE);
	}
	if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &tmp, sizeof(tmp)) < 0) {
		core::log << L"ERR: setsockopt failed";
		exit(EXIT_FAILURE);
	}
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		core::log << L"ERR: bind failed";
		exit(EXIT_FAILURE);
	}

	if (listen(sockfd, bacclog) != 0) {
		core::log << L"ERR: listen failed";
		exit(EXIT_FAILURE);
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
		exit(EXIT_FAILURE);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, keyfd, SSL_FILETYPE_PEM) <= 0) {
		core::log << L"ERR: unable to read SSL key file";
		exit(EXIT_FAILURE);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		core::log << L"ERR: private key doesnt match the public certificate";
		exit(EXIT_FAILURE);
	}
}


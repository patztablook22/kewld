namespace core {

bool iz_k(wint_t);
bool iz_k(std::wstring);
std::wstring trim(std::wstring);
void quit(int);

class cfg {
public:
	void operator<<(std::string);
	std::string gdir();
	class sub_cfg {
	public:
		friend void cfg::operator<<(std::string);
	protected:
		virtual void operator<<(std::wstring) = 0;
	};
private:
	std::map<std::wstring, sub_cfg *> extract;
	std::string dir;
public:
	class port: public sub_cfg {
	public:
		port();
		int gval();
		friend void cfg::operator<<(std::string);
	protected:
		void operator<<(std::wstring);
		int val;
	} port;

	class clientz: public sub_cfg {
	public:
		clientz();
		int gval();
		friend void cfg::operator<<(std::string);
	protected:
		void operator<<(std::wstring);
		int val;
	} clientz;

	class passwd: public sub_cfg {
	public:
		passwd();
		std::wstring gval();
		friend void cfg::operator<<(std::string);
	protected:
		void operator<<(std::wstring);
		std::wstring val;
	} passwd;
	
	class attemptz: public sub_cfg {
	public:
		attemptz();
		int gval();
		friend void cfg::operator<<(std::string);
	protected:
		void operator<<(std::wstring);
		int val;
	} attemptz;

	class certfd: public sub_cfg {
	public:
		certfd();
		std::string gval();
		friend void cfg::operator<<(std::string);
	protected:
		void operator<<(std::wstring);
		std::string val;
	} certfd;

	class keyfd: public sub_cfg {
	public:
		keyfd();
		std::string gval();
		friend void cfg::operator<<(std::string);
	protected:
		void operator<<(std::wstring);
		std::string val;
	} keyfd;

	class name: public sub_cfg {
	public:
		name();
		std::wstring gval();
		friend void cfg::operator<<(std::string);
	protected:
		void operator<<(std::wstring);
		std::wstring val;
	} name;

	class hoi_msg: public sub_cfg {
	public:
		hoi_msg();
		std::wstring gval();
		friend void cfg::operator<<(std::string);
	protected:
		void operator<<(std::wstring);
		std::wstring val;
	} hoi_msg;

	class boi_msg: public sub_cfg {
	public:
		boi_msg();
		std::wstring gval();
		friend void cfg::operator<<(std::string);
	protected:
		void operator<<(std::wstring);
		std::wstring val;
	} boi_msg;

	class conn_delay: public sub_cfg {
	public:
		conn_delay();
		int gval();
		friend void cfg::operator<<(std::string);
	protected:
		void operator<<(std::wstring);
		int val;
	} conn_delay;

	class passwd_invalid_delay: public sub_cfg {
	public:
		passwd_invalid_delay();
		int gval();
		friend void cfg::operator<<(std::string);
	protected:
		void operator<<(std::wstring);
		int val;
	} passwd_invalid_delay;

	class flood_delay: public sub_cfg {
	public:
		flood_delay();
		int gval();
		friend void cfg::operator<<(std::string);
	protected:
		void operator<<(std::wstring);
		int val;
	} flood_delay;
} cfg;

class serv {
public:
	serv(), ~serv();
	void init();
	void listener();
	class msg {
	public:
		msg(), msg(std::wstring), msg(std::wstring, std::wstring);
		std::wstring gusr(), gbody(), gtrg();
		bool gvalid();
		void operator=(msg);
	private:
		std::wstring usr, body, trg;
		bool valid;
	};

private:
	class handler {
	public:
		handler(SSL *), ~handler();
		void operator<<(msg);
		std::wstring gusr();
		bool gready();
	private:
		void imma_ready();
		void operator<<(std::wstring);
		void operator<<(int);
		void operator>>(int &);
		void operator>>(std::wstring &);
		void operator>>(msg &);
		void sniffer();
		SSL *ssl;
		std::wstring usr;
		bool ready;
	};

	class nexus {
	public:
		~nexus();
		void operator<<(msg);
		int join(std::wstring &, handler *);
		int leave(handler *);
		int connno();
		int connno(std::vector<std::wstring> &);
	private:
		std::map<std::wstring, handler *> connected;
	} nexus;

	int serve(int, int);
	SSL_CTX *init_ctx();
	void load_certificatez(const char *, const char *);
	SSL_CTX *ctx;
	int servsock;
} serv;

#include "core/toolz.cpp"
#include "core/cfg.cpp"
#include "core/serv.cpp"
}

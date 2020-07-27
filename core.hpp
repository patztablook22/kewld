namespace core {

/*********************************************************************************************/

bool iz_k(wint_t);
bool iz_k(std::wstring);
std::wstring trim(std::wstring);
void quit(int);
std::wstring sha256(std::wstring);

class cfg {
public:
	void init();
	class sub_cfg {
	public:
		friend void cfg::init();
	protected:
		virtual void operator<<(std::wstring) = 0;
	};
private:
	std::map<std::wstring, sub_cfg *> extract;
public:
	class logfd: public sub_cfg {
	public:
		logfd();
		std::string gval();
		friend void cfg::init();
	protected:
		void operator<<(std::wstring);
		std::string val;
	} logfd;

	class usrz_dir: public sub_cfg {
	public:
		usrz_dir();
		std::string gval();
		friend void cfg::init();
	protected:
		void operator<<(std::wstring);
		std::string val;
	} usrz_dir;

	class port: public sub_cfg {
	public:
		port();
		int gval();
		friend void cfg::init();
	protected:
		void operator<<(std::wstring);
		int val;
	} port;

	class drop_timeout : public sub_cfg {
	public:
		drop_timeout();
		timeval gval();
		friend void cfg::init();
	protected:
		void operator<<(std::wstring);
		timeval val;
	} drop_timeout;

	class clientz: public sub_cfg {
	public:
		clientz();
		int gval();
		friend void cfg::init();
	protected:
		void operator<<(std::wstring);
		int val;
	} clientz;

	class passwd: public sub_cfg {
	public:
		passwd();
		std::wstring gval();
		bool gon();
		friend void cfg::init();
	protected:
		void operator<<(std::wstring);
		bool on;
		std::wstring val;
	} passwd;
	
	class attemptz: public sub_cfg {
	public:
		attemptz();
		int gval();
		friend void cfg::init();
	protected:
		void operator<<(std::wstring);
		int val;
	} attemptz;

	class certfd: public sub_cfg {
	public:
		certfd();
		std::string gval();
		friend void cfg::init();
	protected:
		void operator<<(std::wstring);
		std::string val;
	} certfd;

	class keyfd: public sub_cfg {
	public:
		keyfd();
		std::string gval();
		friend void cfg::init();
	protected:
		void operator<<(std::wstring);
		std::string val;
	} keyfd;

	class name: public sub_cfg {
	public:
		name();
		std::wstring gval();
		friend void cfg::init();
	protected:
		void operator<<(std::wstring);
		std::wstring val;
	} name;

	class hoi_msg: public sub_cfg {
	public:
		hoi_msg();
		std::wstring gval();
		friend void cfg::init();
	protected:
		void operator<<(std::wstring);
		std::wstring val;
	} hoi_msg;

	class boi_msg: public sub_cfg {
	public:
		boi_msg();
		std::wstring gval();
		friend void cfg::init();
	protected:
		void operator<<(std::wstring);
		std::wstring val;
	} boi_msg;

	class ded_msg: public sub_cfg {
	public:
		ded_msg();
		std::wstring gval();
		friend void cfg::init();
	protected:
		void operator<<(std::wstring);
		std::wstring val;
	} ded_msg;

	class conn_delay: public sub_cfg {
	public:
		conn_delay();
		int gval();
		friend void cfg::init();
	protected:
		void operator<<(std::wstring);
		int val;
	} conn_delay;

	class passwd_incorrect_delay: public sub_cfg {
	public:
		passwd_incorrect_delay();
		int gval();
		friend void cfg::init();
	protected:
		void operator<<(std::wstring);
		int val;
	} passwd_incorrect_delay;

	class flood_delay: public sub_cfg {
	public:
		flood_delay();
		int gval();
		friend void cfg::init();
	protected:
		void operator<<(std::wstring);
		int val;
	} flood_delay;

	class flood_msg: public sub_cfg {
	public:
		flood_msg();
		std::wstring gval();
		friend void cfg::init();
	protected:
		void operator<<(std::wstring);
		std::wstring val;
	} flood_msg;

	class allow_registration: public sub_cfg {
	public:
		allow_registration();
		bool gval();
		friend void cfg::init();
	protected:
		void operator<<(std::wstring);
		bool val;
	} allow_registration;

	class registered_only: public sub_cfg {
	public:
		registered_only();
		bool gval();
		friend void cfg::init();
	protected:
		void operator<<(std::wstring);
		bool val;
	} registered_only;
} cfg;

/*********************************************************************************************/

class log {
public:
	log(), ~log();
	void init(), psss(), close();
	void operator<<(std::wstring);
private:
	bool cio;
	std::wofstream fd;
} log;

/*********************************************************************************************/

class usrz {
public:
	void init();
	uint8_t registration(std::wstring, std::wstring), chpasswd(std::wstring, std::wstring);
	uint8_t chomg(std::wstring, wchar_t, uint8_t);

	class omg {
	public:
		omg(), omg(std::wstring);
		bool iz_k();
		uint8_t go(), gm(), gg();
		std::wstring gv();
		void operator=(omg);
	private:
		uint8_t val[3];
	};

	class usr {
	public:
		usr(std::wstring);
		bool iz_k();
		bool auth(std::wstring);
		core::usrz::omg omg;
		bool gbypass();
		void operator=(usr);
	private:
		std::wstring nick, passwd;
		bool bypass, k;
	};
} usrz;

/*********************************************************************************************/

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

	class handler {
	public:
		handler(SSL *), ~handler();
		void operator<<(msg);
		std::thread::id gtid();
		std::wstring gusr();
		bool gready();
		uint8_t gdisconn_t();
		usrz::usr *usrdata;
		uint8_t kick();
		timeval glast();
	private:
		void imma_ready();
		void operator<<(std::wstring);
		void operator<<(int);
		void operator>>(int &);
		void operator>>(std::wstring &);
		void operator>>(msg &);
		void sniffer();
		SSL *ssl;
		std::thread::id tid;
		std::wstring usr;
		bool ready;
		uint8_t disconn_t;
		timeval last;
	};

	class nexus {
	public:
		~nexus();
		void operator<<(msg);
		bool gready(std::wstring);
		int join(std::wstring &, handler *);
		int leave(handler *);
		int kick(std::wstring);
		int connno();
		int connno(std::vector<std::wstring> &);
		handler *diz_handler();
		core::usrz::usr gusrdata(std::wstring);
		std::wstring glast(std::wstring);
	private:
		std::map<std::wstring, handler *> connected;
		std::map<std::thread::id, handler *> threadz;
	} nexus;
private:
	int serve(int, int);
	SSL_CTX *init_ctx();
	void load_certificatez(const char *, const char *);
	SSL_CTX *ctx;
	int servsock;
} serv;

/*********************************************************************************************/

class exec {
public:
	std::wstring escape(std::wstring);
	size_t interpreter(std::wstring, std::vector<std::wstring> &, size_t = -1);

	class cmd {
	public:
		virtual uint8_t do_it(std::vector<std::wstring>) = 0;
	};

	void operator<<(std::wstring);

	void add(std::wstring, cmd *);
private:
	std::map<std::wstring, cmd *> cmdz;
} exec;

/*********************************************************************************************/

#include "core/toolz.cpp"
#include "core/cfg.cpp"
#include "core/log.cpp"
#include "core/usrz.cpp"
#include "core/serv.cpp"
#include "core/exec.cpp"

namespace cmdz {
	#include "core/cmdz.cpp"
}

}

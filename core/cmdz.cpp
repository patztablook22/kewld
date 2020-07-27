class shutdown: public core::exec::cmd {
public:
	shutdown()
	{
		core::exec.add(L"shutdown", this);
	}

	uint8_t do_it(std::vector<std::wstring> arg)
	{
		if (arg.size() != 1)
			return 2;
		core::serv::handler *diz = core::serv.nexus.diz_handler();
		if (diz->usrdata->omg.go() < 1)
			return 3;
		raise(SIGTERM);
		return 0;
	}
} shutdown;

class omg: public core::exec::cmd {
public:
	omg()
	{
		core::exec.add(L"omg", this);
	}

	uint8_t do_it(std::vector<std::wstring> arg)
	{
		if (arg.size() != 1)
			return 2;
		core::serv::handler *diz = core::serv.nexus.diz_handler();
		*diz << core::serv::msg(L"serv", L"ur permissionz: \\1" + diz->usrdata->omg.gv());
		return 0;
	}
} omg;

class kick: public core::exec::cmd {
public:
	kick()
	{
		core::exec.add(L"kick", this);
	}

	uint8_t do_it(std::vector<std::wstring> arg)
	{
		if (arg.size() != 2)
			return 2;
		core::serv::handler *diz = core::serv.nexus.diz_handler();
		if (diz == NULL)
			return 4;
		if (!diz->usrdata->omg.iz_k())
			return 3;
		core::usrz::omg trg = core::serv.nexus.gusrdata(arg[1]).omg;
		switch (diz->usrdata->omg.gm()) {
		case 0:
			return 3;
		case 1:
			if (!trg.iz_k())
				break;
			if (trg.go() > 0 || trg.gm() > 0 || trg.gg() > 0)
				return 3;
			break;
		case 2:
			if (!trg.iz_k())
				break;
			if (trg.go() > 1 || trg.gm() > 1 || trg.gg() > 1)
				return 3;
		}

		switch (core::serv.nexus.kick(arg[1])) {
		case 0:
			break;
		case 1:
			*diz << core::serv::msg(L"serv", L"ERR: no such usr: \"" + arg[1] + L'"');
			return 1;
		case 2:
			*diz << core::serv::msg(L"serv", L"ERR: hessa still not ready");
			return 1;
		default:
			return 1;
		}
		
		return 0;
	}
} kick;

class say: public core::exec::cmd {
public:
	say()
	{
		core::exec.add(L"say", this);
	}

	uint8_t do_it(std::vector<std::wstring> arg)
	{
		if (arg.size() != 2)
			return 2;
		core::serv::handler *diz = core::serv.nexus.diz_handler();
		if (diz->usrdata->omg.go() == 0 && diz->usrdata->omg.gm() == 0 && diz->usrdata->omg.gg() == 0)
			return 3;
		if (arg[1][0] == L'/') {
			*diz << core::serv::msg(L"serv", L"ERR: msg cannot start with \"/\"");
			return 1;
		}
		core::serv.nexus << core::serv::msg(L"serv", arg[1]);
		return 0;
	}
} say;

class chomg: public core::exec::cmd {
public:
	chomg()
	{
		core::exec.add(L"chomg", this);
	}

	uint8_t do_it(std::vector<std::wstring> arg)
	{
		if (arg.size() != 4)
			return 2;
		if (arg[2].size() != 1)
			return 2;
		wint_t perm = arg[2][0];
		if (perm != L'o' && perm != L'm' && perm != L'g')
			return 2;
		int val;
		try {
			val = std::stoi(arg[3]);
		} catch (...) {
			return 2;
		}
		if (val < 0 || val > 2)
			return 2;

		core::serv::handler *diz = core::serv.nexus.diz_handler();
		core::usrz::omg da_omg = core::serv.nexus.gusrdata(arg[1]).omg;
		if (diz->usrdata->omg.gg() <= da_omg.gg())
			return 3;
		switch (perm) {
		case L'o':
			if (diz->usrdata->omg.gg() < da_omg.go() || diz->usrdata->omg.gg() < val)
				return 3;
			break;
		case L'm':
			if (diz->usrdata->omg.gg() < da_omg.gm() || diz->usrdata->omg.gg() < val)
				return 3;
			break;
		case L'g':
			if (diz->usrdata->omg.gg() <= val)
				return 3;
			break;
		}
		if (!core::serv.nexus.gready(arg[1])) {
			*diz << core::serv::msg(L"serv", L"ERR: usr not online: \"" + arg[1] + L'"');
			return 1;
		}
		switch (core::usrz.chomg(arg[1], perm, val)) {
		case 0:
			break;
		case 255:
			*diz << core::serv::msg(L"serv", L"WARN: same as current value");
			return -1;
		case 1:
			*diz << core::serv::msg(L"serv", L"ERR: usr must be registered 2 obtain omg");
			return 1;
		default:
			return 1;
		}
		core::serv.nexus << core::serv::msg(L"serv", L"/usrz omg \"" + arg[1] + L"\" " + arg[2] + L' ' + arg[3]);
		return 0;
	}
} chomg;

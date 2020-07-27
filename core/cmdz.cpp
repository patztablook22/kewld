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
		if (diz->permz.go() < 1)
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
		std::wstring permz;
		switch (diz->permz.go()) {
		default:
			permz += L'-';
			break;
		case 1:
			permz += L'o';
			break;
		case 2:
			permz += L'O';
		}
		switch (diz->permz.gm()) {
		default:
			permz += L'-';
			break;
		case 1:
			permz += L'm';
			break;
		case 2:
			permz += L'M';
			break;
		}
		switch (diz->permz.gg()) {
		default:
			permz += L'-';
			break;
		case 1:
			permz += L'g';
			break;
		case 2:
			permz += L'G';
			break;
		}
		*diz << core::serv::msg(L"serv", L"ur permissionz: " + permz);
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
		if (!diz->permz.iz_k())
			return 3;
		core::usrz::omg trg = core::serv.nexus.client_omg(arg[1]);
		switch (diz->permz.gm()) {
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
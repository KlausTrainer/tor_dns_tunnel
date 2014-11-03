PROJECT = tor_dns_tunnel

RELX:=$(shell which relx || echo ./relx)

# options

# standard targets

include erlang.mk

release: clean-release deps all
	$(RELX) -o rel/$(PROJECT) -c rel/reltool.config

clean-release:
	rm -rf rel/$(PROJECT)

clean: clean-release

check test: tests

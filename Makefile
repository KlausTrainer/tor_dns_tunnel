PROJECT = tor_dns_tunnel

RELX:=$(shell which relx || echo ./relx)

# options

# standard targets

include erlang.mk

release: clean-release deps all
	$(RELX) -o rel -c rel/reltool.config

clean-release:
	rm -rf rel/$(PROJECT)

install: release
	sudo ./install $(PROJECT) /usr/local/lib

clean: clean-release

check test: tests

SYSTEM := $(shell uname -o)
PWD := $(shell pwd)

CFLAGS = -I$(PWD)/compat

CFLAGS += -D_LINUX_

all:
	$(MAKE) -C obspamd CFLAGS="$(CFLAGS)" all
	$(MAKE) -C obspamdb all
	$(MAKE) -C obspamd-setup all
	$(MAKE) -C obspamlogd all

clean:
	$(MAKE) -C obspamd clean
	$(MAKE) -C obspamdb clean
	$(MAKE) -C obspamd-setup clean
	$(MAKE) -C obspamlogd clean

install:
	$(MAKE) -C obspamd install
	$(MAKE) -C obspamdb install
	$(MAKE) -C obspamd-setup install
	$(MAKE) -C obspamlogd install


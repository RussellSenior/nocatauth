### Install somewhere else if you've a mind (or aren't root).

INST_PATH  = /usr/local/nocat

### These aren't the droids you're looking for.

INSTALL	    = cp -Ruv 
GPG	    = /usr/bin/gpg

INST_BIN    = bin
INST_GW	    = lib pgp nocat.conf
INST_SERV   = cgi-bin htdocs

all: install

install:
	@echo
	@echo "Nothing to build. Edit the Makefile to suit, then run 'make gateway'"
	@echo "or 'make authserv'."
	@echo

$(INST_PATH): 
	[ -d $(INST_PATH) ] || mkdir $(INST_PATH)
	chmod 755 $(INST_PATH)

install_bin:
	$(INSTALL) $(INST_BIN) $(INST_PATH)
	chmod 755 $(INST_PATH)/$(INST_BIN)/*

gateway: $(INST_PATH) install_bin
	$(INSTALL) $(INST_GW) $(INST_PATH)

authserv: gateway
	$(INSTALL) $(INST_SERV) $(INST_PATH)
	@echo
	@echo "You may wish to run 'make pgpkey' now to generate your service's PGP keys."
	@echo

pgpkey:
	[ -d $(INST_PATH)/pgp ] || mkdir $(INST_PATH)/pgp
	chmod 700 $(INST_PATH)/pgp
	$(GPG) --homedir=$(INST_PATH)/pgp --gen-key
	$(INSTALL) $(INST_PATH)/pgp/pubring.gpg $(INST_PATH)/trustedkeys.gpg


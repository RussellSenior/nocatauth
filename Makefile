### Install somewhere else if you've a mind (or aren't root).

INST_PATH  = /usr/local/nocat

### These aren't the droids you're looking for.

INSTALL	    = cp -dRuv 
INST_BIN    = bin
INST_GW	    = lib pgp htdocs nocat.conf
INST_SERV   = cgi-bin
FW_TYPE	   := $(shell ./detect-fw.sh)

all: install

install:
	@echo
	@echo "Nothing to build. Edit the Makefile to suit, then run 'make gateway'"
	@echo "or 'make authserv'."
	@echo

$(INST_PATH): 
	[ -d $(INST_PATH) ] || mkdir $(INST_PATH)
	chmod 755 $(INST_PATH)

check_fw:
	[ "$(FW_TYPE)" ] || ( echo "Can't seem to find supported firewall software. Check your path?" && exit 255 )

check_gpg:
	which gpg 2>/dev/null  || ( echo "Can't seem to find gpg in your path. Is it installed?"  && exit 255 )

check_gpgv:
	which gpgv 2>/dev/null || ( echo "Can't seem to find gpgv in your path. Is it installed?" && exit 255 )

FORCE:

$(INST_BIN)/$(FW_TYPE)/*: FORCE
	ln -sf $(FW_TYPE)/$(notdir $@) $(INST_BIN)

install_bin:
	$(INSTALL) $(INST_BIN) $(INST_PATH)
	chmod 755 $(INST_PATH)/$(INST_BIN)/*

install_gw: $(INST_PATH) install_bin
	$(INSTALL) $(INST_GW) $(INST_PATH)

gateway: check_fw check_gpgv $(INST_BIN)/$(FW_TYPE)/* install_gw

authserv: check_gpg install_gw
	$(INSTALL) $(INST_SERV) $(INST_PATH)
	@echo
	@echo "You may wish to run 'make pgpkey' now to generate your service's PGP keys."
	@echo

pgpkey: check_gpg
	[ -d $(INST_PATH)/pgp ] || mkdir $(INST_PATH)/pgp
	chmod 700 $(INST_PATH)/pgp
	gpg --homedir=$(INST_PATH)/pgp --gen-key
	$(INSTALL) $(INST_PATH)/pgp/pubring.gpg $(INST_PATH)/trustedkeys.gpg
	@echo
	@echo "The public key ring you'll need to distribute can be found in"
	@echo "	   $(INST_PATH)/trustedkeys.gpg."
	@echo


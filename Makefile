### Install somewhere else if you've a mind (or aren't root).

INST_PATH  = /usr/local/nocat

### These aren't the droids you're looking for.

INSTALL	    = cp -adRu
INST_BIN    = bin
INST_ETC    = etc
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
	@[ -d $(INST_PATH) ] || mkdir $(INST_PATH)
	@chmod 755 $(INST_PATH)

check_fw:
	@echo -n "Checking for firewall compatibility: "
	@[ "$(FW_TYPE)" ] || ( echo "Can't seem to find supported firewall software. Check your path?" && exit 255 )
	@echo "$(FW_TYPE) found."
	
check_gpg:
	@echo "Looking for gpg..."
	@which gpg >/dev/null  || ( echo "Can't seem to find gpg in your path. Is it installed?"  && exit 255 )

check_gpgv:
	@echo "Looking for gpgv..."
	@which gpgv > /dev/null || ( echo "Can't seem to find gpgv in your path. Is it installed?" && exit 255 )

FORCE:

$(INST_BIN)/$(FW_TYPE)/*: FORCE
	@ln -sf $(FW_TYPE)/$(notdir $@) $(INST_BIN)

install_bin:
	@$(INSTALL) $(INST_BIN) $(INST_PATH)

install_etc:
	@$(INSTALL) $(INST_ETC) $(INST_PATH)

install_gw: $(INST_PATH) install_bin
	@echo "Installing NoCat to $(INST_PATH)..."
	@$(INSTALL) $(INST_GW) $(INST_PATH)

gateway: check_fw check_gpgv $(INST_BIN)/$(FW_TYPE)/* install_gw gw_success

authserv: check_gpg install_gw install_etc auth_success
	@$(INSTALL) $(INST_SERV) $(INST_PATH)
	@echo
	@echo "You may wish to run 'make pgpkey' now to generate your service's PGP keys."
	@echo

pgpkey: check_gpg
	@[ -d $(INST_PATH)/pgp ] || mkdir $(INST_PATH)/pgp
	@chmod 700 $(INST_PATH)/pgp
	@gpg --homedir=$(INST_PATH)/pgp --gen-key
	@$(INSTALL) $(INST_PATH)/pgp/pubring.gpg $(INST_PATH)/trustedkeys.gpg
	@echo
	@echo "The public key ring you'll need to distribute can be found in"
	@echo "	   $(INST_PATH)/trustedkeys.gpg."
	@echo

gw_success: install_gw
	@echo
	@echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
	@echo "                  Congratulations!"
	@echo "  NoCat gateway is installed.  To start it, check"
	@echo "  $(INST_PATH)/nocat.conf, then run bin/gateway"
	@echo "  as root."
	@echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
	@echo

auth_success: install_gw
	@echo
	@echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
	@echo "                    Congratulations!"
	@echo "  NoCat Authserv is installed.  Add etc/authserv.conf"
	@echo "  to your Apache configuration, build your database,"
	@echo "  and GOOD LUCK!"
	@echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
	@echo

### Install somewhere else if you've a mind (or aren't root).

PREFIX	    = /usr/local/nocat

### These aren't the droids you're looking for.

INSTALL	    = cp -R
INST_BIN    = bin
INST_ETC    = etc
INST_GW	    = lib pgp
INST_FORMS  = htdocs
INST_SERV   = cgi-bin

all: install

install:
	@echo
	@echo "Nothing to build. Edit the Makefile to suit, then run 'make gateway'"
	@echo "or 'make authserv'."
	@echo

$(PREFIX): 
	[ -d $(PREFIX) ] || mkdir $(PREFIX)
	chmod 755 $(PREFIX)

check_fw:
	@echo -n "Checking for firewall compatibility: "
	@bin/detect-fw.sh bin || ( echo "Can't seem to find supported firewall software. Check your path?" && exit 255 )
	
check_gpg:
	@echo "Looking for gpg..."
	@which gpg >/dev/null  || ( echo "Can't seem to find gpg in your path. Is it installed?"  && exit 255 )

check_gpgv:
	@echo "Looking for gpgv..."
	@which gpgv > /dev/null || ( echo "Can't seem to find gpgv in your path. Is it installed?" && exit 255 )

install_bin:
	$(INSTALL) $(INST_BIN) $(PREFIX)

install_etc:
	$(INSTALL) $(INST_ETC) $(PREFIX)

install_forms:
	[ -d $(PREFIX)/$(INST_FORMS) ] || $(INSTALL) $(INST_FORMS) $(PREFIX)

install_gw: $(PREFIX) install_forms install_bin
	@echo "Installing NoCat to $(PREFIX)..."
	$(INSTALL) $(INST_GW) $(PREFIX)

gateway: check_fw check_gpgv install_gw
	[ -f $(PREFIX)/nocat.conf ] || \
	    perl -pe 's#/usr/local/nocat#$(PREFIX)#g' gateway.conf \
		> $(PREFIX)/nocat.conf
	@echo
	@echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
	@echo "                  Congratulations!"
	@echo "  NoCat gateway is installed.  To start it, check"
	@echo "  $(PREFIX)/nocat.conf, then run bin/gateway"
	@echo "  as root."
	@echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
	@echo


authserv: check_gpg install_gw install_etc
	$(INSTALL) $(INST_SERV) $(PREFIX)
	[ -f $(PREFIX)/nocat.conf ] || \
	    perl -pe 's#/usr/local/nocat#$(PREFIX)#g' authserv.conf \
		> $(PREFIX)/nocat.conf
	[ -f $(PREFIX)/httpd.conf ] || \
	    perl -pe 's#/usr/local/nocat#$(PREFIX)#g' etc/authserv.conf \
		> $(PREFIX)/httpd.conf
	@echo
	@echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
	@echo
	@echo "  Congratulations! NoCat Authserv is installed."
	@echo
	@echo "  You will find a database schema in etc/nocat.schema."
	@echo
	@echo "  You will find suitable defaults to include in your Apache configuration"
	@echo "    in $(PREFIX)/httpd.conf".
	@echo
	@echo "  You may wish to run 'make pgpkey' now to generate your service's PGP keys."
	@echo
	@echo "  GOOD LUCK!"
	@echo
	@echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
	@echo

pgpkey: check_gpg
	[ -d $(PREFIX)/pgp ] || mkdir $(PREFIX)/pgp
	chmod 700 $(PREFIX)/pgp
	gpg --homedir=$(PREFIX)/pgp --gen-key
	$(INSTALL) $(PREFIX)/pgp/pubring.gpg $(PREFIX)/trustedkeys.gpg
	@echo
	@echo "Be sure to make your $(PREFIX)/pgp directory readable *only* by the user"
	@echo "    your httpd runs as."
	@echo
	@echo "The public key ring you'll need to distribute can be found in"
	@echo "	   $(PREFIX)/trustedkeys.gpg."
	@echo


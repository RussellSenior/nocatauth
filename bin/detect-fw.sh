#!/bin/sh

export PATH=$PATH:/sbin:/usr/sbin:/usr/local/sbin

# Have we been explicitly told which firewall scripts to install?
if [ -n "$1" -a -n "$2" -a -d "$2/$1" ]; then
    FIREWALL=$1
    shift

# Do we have iptables *and* are running Linux 2.4?
#
elif [ "$(which iptables 2>/dev/null)" -a \
     "$(uname -sr | cut -d. -f-2)" = "Linux 2.4" ]; then
    FIREWALL=iptables

#
# Or do we have ipchains?
#
elif [ $(which ipchains 2>/dev/null) ]; then
    FIREWALL=ipchains

#
# Or ip_filter (e.g. *BSD, Solaris, HP-UX, etc)?
# <http://www.ipfilter.org/>
#
elif [ $(which ipf 2>/dev/null) ]; then
ipf_running="`ipf -V | grep 'Running' | awk '{print $2}'`";
    if [ "$ipf_running" = "yes" ]; then
	FIREWALL="ipfilter"
    else
        echo "ERROR: ip_filter appears to exist, but we're not postive that it's running"
	echo "1. You must be root for us to verify this"
        echo "2. Check that it's compiled in your kernel (either staticlly or a loaded module)"
    fi

# Or packetfilter (OpenBSD 3.0+)
elif [ $(which pfctl 2>/dev/null) ]; then
    FIREWALL=pf

else
    echo "No supported firewalls detected! Check your path."
    echo "Supported firewalls include: iptables, ipchains, ipf, pf."
    exit 1
fi

echo "$FIREWALL found."

# Remove the existing *.fw links in /usr/local/nocat/bin (or wherever this is being run from)
TARGET=$1
if [ -n "$TARGET" ]; then
    rm -f $TARGET/*.fw

    # Then add new symlinks for each *.fw file in the appropriate firewall directory.
    for script in $TARGET/$FIREWALL/*.fw; do
	src=$FIREWALL/$(basename $script)
	dest=$TARGET/$(basename $script)
	echo "$src -> $dest"
	ln -sf $src $dest
    done
fi

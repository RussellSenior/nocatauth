#!/bin/sh

export PATH=$PATH:/sbin:/usr/sbin:/usr/local/sbin

# Do we have iptables *and* are running Linux 2.4?
#
if [ "$(which iptables 2>/dev/null)" -a \
     "$(uname -sr | cut -d. -f-2)" = "Linux 2.4" ]; then
    echo iptables

#
# Or do we have ipchains?
#
elif [ $(which ipchains 2>/dev/null) ]; then
    echo ipchains

#
# Or ip_filter (e.g. *BSD, Solaris, HP-UX, etc)?
# <http://www.ipfilter.org/>
#
elif [ $(which ipf 2>/dev/null) ]; then
ipf_running="`ipf -V | grep 'Running' | awk '{print $2}'`";
        if [ "$ipf_running" = "yes" ]; then
                echo "ipfilter"
        else
		echo ""
                echo "ERROR: ip_filter appears to exist, but we're not postive that it's running"
		echo "1. You must be root for us to verify this"
                echo "2. Check that it's compiled in your kernel (either staticlly or a loaded module)"
        fi
fi

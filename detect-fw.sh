#!/bin/bash

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
# Or ipfilter (e.g. *BSD)?
#
elif [ $(which ipf 2>/dev/null) ]; then
    echo ipfilter
fi

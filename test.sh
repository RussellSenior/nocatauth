#/bin/sh
find lib -name '*.pm' | xargs -n1 perl -cwIlib
find bin/{gateway,admintool} cgi-bin -perm +0111 -type f | xargs -n1 perl -cwIlib

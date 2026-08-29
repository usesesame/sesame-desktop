#!/bin/sh
# deb runs this as prerm with "remove" on a real removal and "upgrade" while
# upgrading; rpm runs it as %preun with 0 on a real removal and 1 while
# upgrading. Cleanup must not block package removal.
if [ "$1" = "remove" ] || [ "$1" = "0" ]; then
  /usr/bin/sesame-browser-host unregister || true
fi

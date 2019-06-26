#!/bin/sh
#
# docker-entrypoint.sh
#
# The Dockerfile CMD, or any "docker run" command option, gets
# passed as command-line arguments to this script.

# Abort on any error (good shell hygiene)
set -e

# Execute confd
confd -onetime -backend env

# If we're running "twping_exporter.py", provide default options
if [ "$1" = "twamp_exporter" ]; then
  # Remove the command from the option list (we know it)
  shift

  # Then run it with default options plus whatever else
  # was given in the command
  exec twamp_exporter -c /opt/twamp_exporter/twamp.ini "$@"
fi

# Otherwise just launch whatever is passed by docker
# (i.e. the CMD instruction in the Dockerfile)
exec "$@"
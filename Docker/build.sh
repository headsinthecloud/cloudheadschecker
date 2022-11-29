#!/usr/bin/env bash
set -e
[ -d pkg ] || mkdir pkg
cp ../dist/cloudheadschecker-0.0.1.tar.gz pkg/
docker  build -t 'cloudheadschecker:latest' .
echo
echo "you can now invoke cloudheadschecker as follows:"
echo "single shot via: "
echo "# docker run -it --rm cloudheadschecker cloudheadschecker [ARGUMENTS]"
echo "or using a shell: "
echo "# docker run -it --rm cloudheadschecker"

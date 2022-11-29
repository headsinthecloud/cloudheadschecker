#!/usr/bin/env bash
set -e
docker  build -t 'cloudheadschecker:latest' .
cat <<EOF

you can now invoke cloudheadschecker as follows:

single shot:

  # docker run -it --rm cloudheadschecker cloudheadschecker [ARGUMENTS]

or using a shell:

  # docker run -it --rm cloudheadschecker"

to export the image, use:

# docker save cloudheadschecker:latest | gzip > cloudheadschecker.tgz

EOF

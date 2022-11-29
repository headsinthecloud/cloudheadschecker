#!/bin/bash
set -e

rm -Rf dist/
./setup.py sdist
./setup.py bdist

echo
echo

echo "You can now pip install the source or binary distribution using one of the following commands:"
for d in dist/*.tar.gz; do
  echo "# pip install $d"
done

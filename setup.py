#!/usr/bin/env python3

#  Copyright (c) 2022. Anonymous Authors
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

import re
import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

package_name = "cloudheadschecker"

VERSIONFILE = "%s/_version.py" % package_name
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
    print("found version %s" % verstr)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))


setuptools.setup(
        name=package_name,
        version=verstr,
        author="Anonymous Authors",
        # author_email="",
        author_email="",
        description="Checks for cloud services",
        long_description=long_description,
        long_description_content_type="text/markdown",
        url="",
        setup_requires=['wheel'],
        packages=setuptools.find_packages(),
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
            "Operating System :: OS Independent",
            ],
        entry_points={
            'console_scripts': [
                'cloudheadschecker=cloudheadschecker.checker:main',
                ],
            },
        install_requires=[
            'dnspython==2.2.1',
            'publicsuffixlist==0.9.1',
            'requests==2.28.1',
            ],
        python_requires='>=3.8',
        )

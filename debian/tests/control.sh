#!/bin/sh

echo "Generating the debian/tests/control file..."

echo "# DON'T MANUALLY MODIFY!" > debian/tests/control.tmp
echo "# EDIT debian/tests/control.in INSTEAD!" >> debian/tests/control.tmp
echo "#" >> debian/tests/control.tmp

cat debian/tests/control.in >> debian/tests/control.tmp

sed -i "s#%RECOMMENDS%#$(bin/diffoscope --list-debian-substvars | awk -F= '/diffoscope:Recommends/ { print $2 }')#" debian/tests/control.tmp

sed -i "s#%PYRECOMMENDS%#$(python3 -c "import distutils.core; \
	setup = distutils.core.run_setup('setup.py'); \
	print(', '.join(sorted(['python3-{}'.format(x) for y in setup.extras_require.values() for x in y])))" \
)#" debian/tests/control.tmp

# Don't test-depend on radare2; not in bullseye for security reasons. (#950372)
sed -i "s#radare2, ##" debian/tests/control.tmp

sed -i "s,python3-python-debian,python3-debian," debian/tests/control.tmp
sed -i "s,python3-rpm-python,python3-rpm," debian/tests/control.tmp
sed -i "s,apktool,apktool [!ppc64el !s390x]," debian/tests/control.tmp
sed -i "s,fp-utils,fp-utils [!ppc64el !s390x]," debian/tests/control.tmp
sed -i "s,oggvideotools,oggvideotools [!s390x]," debian/tests/control.tmp

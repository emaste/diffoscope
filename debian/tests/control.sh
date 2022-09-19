#!/bin/sh

echo "Generating the debian/tests/control file..."

cat > debian/tests/control.tmp << EOF
# DON'T MANUALLY MODIFY!
# EDIT debian/tests/control.in INSTEAD!
#
EOF

cat debian/tests/control.in >> debian/tests/control.tmp

sed -i "s#%RECOMMENDS%#$(bin/diffoscope --list-debian-substvars | awk -F= '/diffoscope:Recommends/ { print $2 }')#" debian/tests/control.tmp

sed -i "s#%PYRECOMMENDS%#$(python3 -c "from pep517 import meta; \
	from pip._internal.req.constructors import install_req_from_req_string; \
	dist = meta.load('.'); \
	print(', '.join([f'python3-{install_req_from_req_string(req).name}' for req in sorted(dist.requires) if install_req_from_req_string(req).markers]))" \
)#" debian/tests/control.tmp

# Don't test-depend on radare2; not in bullseye for security reasons. (#950372)
sed -i "s#radare2, ##" debian/tests/control.tmp

sed -i "s,python3-python-debian,python3-debian," debian/tests/control.tmp
sed -i "s,python3-rpm-python,python3-rpm," debian/tests/control.tmp
sed -i "s,apktool,apktool [!ppc64el !s390x]," debian/tests/control.tmp
sed -i "s,fp-utils,fp-utils [!ppc64el !s390x]," debian/tests/control.tmp
sed -i "s,oggvideotools,oggvideotools [!s390x]," debian/tests/control.tmp
sed -i "s,python3-androguard,androguard," debian/tests/control.tmp

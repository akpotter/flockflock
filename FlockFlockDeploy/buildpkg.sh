#!/bin/bash

BUILD=$1

if [ "$1x" == "x" ]
then
    echo "syntax: $0 [build_number]"
    exit
fi
IDENTITY="Jonathan Zdziarski"

pkgbuild --root `pwd`/root --identifier com.zdziarski.FlockFlock --version $BUILD --ownership recommended --install-location / --sign "$IDENTITY" FlockFlock.pkg

productbuild --synthesize --product requirements.plist --package FlockFlock.pkg distribution.plist

sed -i "" -e 's/onConclusion="none"/onConclusion="RequireRestart"/' distribution.plist

sed -i "" -e 's/<\/installer-gui-script>/<readme mime-type=\"application\/rtf\" file=\"README.rtf\"\/><\/installer-gui-script>/' distribution.plist
sed -i "" -e 's/<\/installer-gui-script>/<license mime-type=\"application\/rtf\" file=\"LICENSE.rtf\"\/><\/installer-gui-script>/' distribution.plist

productbuild --sign "$IDENTITY" --distribution distribution.plist --resources . --package-path FlockFlock.pkg FlockFlock-$BUILD.pkg
rm -f FlockFlock.pkg
rm -f distribution.plist


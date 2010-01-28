# Copyright 2004 Rainer Wichmann
# Distributed under the terms of the GNU General Public License v2

inherit eutils

MY_P="${PN}_signed-${PV}"
SLOT="0"
LICENSE="GPL-2"
DESCRIPTION="Samhain is a file integrity checker with optional central logging"

# This is a fake URI that allows us to do a 'make dist' and copy
# the file to distdir. 
# The proper URI would be http://www.la-samhna.de/archive/${MY_P}.tar.gz,
# but this would force us to do a 'make dist-sign' ...
# Apparently, portage cannot handle the file:// scheme,
# and not every user might be prepared to create a signed tarball.
#
# SRC_URI="http://www.la-samhna.de/archive/${MY_P}.tar.gz"
SRC_URI="http://www.la-samhna.de/archive/${P}.tar.gz"


HOMEPAGE="http://www.la-samhna.de/samhain/"

KEYWORDS="x86"

IUSE=""

DEPEND="app-arch/gzip
	app-arch/tar"
#	mysql? (>=dev-db/mysql-3.23.58)"
RDEPEND=""

src_unpack() {
        unpack ${A}
        cd ${WORKDIR}
        if test -f ${P}.tar.gz; then
	   gunzip -c ${P}.tar.gz | tar xf -  || die
	   cd ${P}
	elif test -d "samhain-${PV}"; then
	   mv "samhain-${PV}" "yule-${PV}"
	fi
}

src_compile() {
	local myconf="--with-trusted=0,250"

#	myconf="$myconf --enable-mounts-check"
#	myconf="$myconf --enable-userfiles"

#	use mysql    && myconf="$myconf --with-database=mysql"
#	use postgres && myconf="$myconf --with-database=postgresql"

#        econf \
#	      --with-pid-file=/var/run/${PN}.pid \
#	      --with-state-dir=/var/lib/${PN} \
#	      --with-log-file=/var/log/${PN}.log \

	./configure ${myconf} --enable-base=11190108,811868198  '--with-trusted=0,2,1000' '--enable-xml-log' '--enable-debug' '--enable-network=server' '--prefix=/home/rainer/PROJECTS/samhain/devel' '--localstatedir=/home/rainer/PROJECTS/samhain/devel' '--with-config-file=REQ_FROM_SERVER/home/rainer/PROJECTS/samhain/devel/testrc_2' '--with-data-file=REQ_FROM_SERVER/home/rainer/PROJECTS/samhain/devel/.samhain_file' '--with-logserver=127.0.0.1' '--with-log-file=/home/rainer/PROJECTS/samhain/devel/.samhain_log' '--with-pid-file=/home/rainer/PROJECTS/samhain/devel/.samhain_lock' '--with-database=postgresql' 'CC=' || die
        emake || die

	echo '#!/bin/sh' > ./sstrip
	echo 'echo "*** SSTRIP DISABLED ***"' >> ./sstrip
}

src_install() {
        make DESTDIR=${D} install  || die
        make DESTDIR=${D} install-boot  || die

	dodoc docs/BUGS COPYING docs/Changelog LICENSE docs/README \
	      docs/README.UPGRADE docs/sh_mounts.txt docs/sh_userfiles.txt \
	      docs/MANUAL-2_3.ps docs/MANUAL-2_3.html.tar

	dohtml docs/HOWTO-client+server.html docs/HOWTO-samhain+GnuPG.html \
	       docs/HOWTO-write-modules.html docs/HOWTO-samhain-on-windows.html \
	       docs/HOWTO-client+server-troubleshooting.html docs/FAQ.html 
}

pkg_prerm() {
	rc-update del yule
	einfo "Stopping service yule"
	test -f /etc/init.d/yule && /etc/init.d/yule stop
	sleep 3
}

pkg_postinst() {
	rc-update add yule default
	einfo
        einfo "yule is installed but is NOT running yet, and the database"
	einfo "of file signatures is NOT initialized yet."
	einfo
	einfo "You need to run \"yule -t init\" to initialize "
        einfo "the baseline database of file signatures."
        einfo
	einfo "After initializing the database, you can start yule "
	einfo "with \"/etc/init.d/yule start\". It is configured to start"
	einfo "automatically on the next boot for runlevel \"default\""
}	      


#! /bin/sh

#
# Copyright Rainer Wichmann (2006)
#
# License Information:
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

# dnmalloc + flawfinder + (36 * 3)
MAXTEST=116; export MAXTEST

run_dnmalloc ()
{
    fail=0
    if test x$1 = x0; then
	[ -z "$verbose" ]     ||  log_msg_ok  "configure...";
	$MAKE clean > /dev/null 2>> test_log
	$MAKE test_dnmalloc > /dev/null 2>> test_log
	if test x$? = x0; then
	    [ -z "$verbose" ] || log_msg_ok   "make test_dnmalloc...";
 	else
	    [ -z "$quiet" ] &&   log_msg_fail "make test_dnmalloc...";
	    fail=1
	fi
    else
	[ -z "$quiet" ] &&       log_msg_fail "configure...";
	if [ x"$3" = xskip ]; then
	    [ -z "$quiet" ] && log_skip $2 ${MAXTEST} "test dnmalloc";
	fi
	fail=1
    fi
    if [ $fail -eq 1 ]; then
	[ -z "$quiet" ] && log_fail $2 ${MAXTEST} "test dnmalloc";
	return 1
    fi
    #
    fail=0
    ./test_dnmalloc >/dev/null
    if test x$? = x0; then
	[ -z "$verbose" ] || log_msg_ok   "run 1 completed...";
	./test_dnmalloc 300 12 3000 150000 400 >/dev/null
	if test x$? = x0; then
	    [ -z "$verbose" ] || log_msg_ok   "run 2 completed...";
	    ./test_dnmalloc 1 1 4000 10000000 1000 >/dev/null
	    if test x$? = x0; then
		[ -z "$verbose" ] || log_msg_ok   "run 3 completed...";
		./test_dnmalloc 1 1 4000 10000000 1000 >/dev/null
		if test x$? = x0; then
		    [ -z "$verbose" ] || log_msg_ok   "run 4 completed...";
		else
		    fail=1
		fi
	    else
		fail=1
	    fi
	else
	    fail=1
	fi
    else
	fail=1
    fi
    #
    if test x$fail = x0; then
	[ -z "$quiet" ] &&     log_ok   $2 ${MAXTEST} "test dnmalloc";
	return 0
    else
	[ -z "$quiet" ] && log_fail $2 ${MAXTEST} "test dnmalloc";
	return 1
    fi
}

run_uno ()
{
    if [ -z "$doall" ]; then
	[ -z "$quiet" ] && log_skip $2 ${MAXTEST} "$TEST (uno)";
	return 0
    fi
    #
    UNO=`find_path uno`
    #
    if [ -z "$UNO" ]; then
	log_skip $num $MAXTEST 'check w/uno (not in PATH)'
	return 0
    fi
    #
    cd src/
    stat=`uno -DHAVE_MMAP=1 -DUSE_UNO=1 -t -I. -I.. -I../include sh_*.c samhain.c slib.c dnmalloc.c zAVLTree.c trustfile.c rijndael-*.c bignum.c 2>&1 | wc -l`
    if [ $stat -ne 1 ]; then
	uno -DSH_WITH_CLIENT -DSH_WITH_SERVER -DHAVE_MMAP=1 -DUSE_UNO=1 -t -I. -I.. -I../include sh_*.c samhain.c slib.c dnmalloc.c zAVLTree.c trustfile.c rijndael-*.c bignum.c >>../test_log 2>&1
	retval=1
	[ -z "$quiet" ] && log_fail $2 ${MAXTEST} "$TEST (uno)";
    else
	retval=0
	[ -z "$quiet" ] &&     log_ok   $2 ${MAXTEST} "$TEST (uno)";
    fi
    cd ..
    return $retval
}

run_flawfinder ()
{
    flawfinder --minlevel=3 --quiet src/s*.c | \
	egrep '^No hits found.' >/dev/null 2>&1
    if [ $? -eq 0 ]; then
	[ -z "$quiet" ] &&     log_ok   $2 ${MAXTEST} "$TEST";
    else
	flawfinder --minlevel=3 --quiet src/s*.c >test_log 2>&1
	[ -z "$quiet" ] && log_fail $2 ${MAXTEST} "$TEST";
	return 1
    fi
}

run_smatch () 
{
    export CDIR=`pwd`;

    if [ -z "$doall" ]; then
	[ -z "$quiet" ] && log_skip $2 ${MAXTEST} "$TEST (smatch)";
	return 0
    fi

    if [ ! -f "./x_samhain.c.sm" ]; then
	[ -z "$quiet" ] && log_skip $2 ${MAXTEST} "$TEST (skip sm)";
	return 0
    fi

    if [ "x$3" = "xdebug" ]; then memcheck=debug; else memcheck=simple; fi
    if [ -f ../../static/sm_scripts/smatch.pm ]; then
	( 
	    cd ../../static/sm_scripts;
	    
	    for i in ${CDIR}/*.c.sm ; do
	        # echo $i;
		cat $i | ./unreached_code.pl | grep -v sh_threaded_module_run;
		cat $i | ./ampersand_missing.sh;
		cat $i | ./eqeq.pl;
		cat $i | ./for_bounds.pl;    # doesn't work?
		cat $i | ./unchecked_returns.pl;
		cat $i | ./uninitialized.pl; # doesn't work?

		# from http://people.redhat.com/mstefani/wine/smatch/
		if [ -f ./while_for_check.pl ]; then
		    cat $i | ./while_for_check.pl; # works
		fi 
		# --> end wine <--

		# samhain specific modifications (list of free/malloc funcs)
		# doesn't seem to find anything useful
		if [ $memcheck = xsimple ]; then
		    if [ -f ./samhain_unfree.pl ]; then
			cat $i | ./samhain_unfree.pl | \
			    egrep -v 'x_cutest_.*Test_' | \
			    egrep -v 'x_sh_unix.c .... .... sh_unix_copyenv';
		    fi 
		fi
		if [ $memcheck = xdebug ]; then
		    if [ -f ./samhain_unfree_debug.pl ]; then
			cat $i | ./samhain_unfree_debug.pl | \
			    egrep -v 'x_cutest_.*Test_' | \
			    egrep -v 'x_sh_unix.c .... .... sh_unix_copyenv';
		    fi 
		fi
		# --> end samhain specific <--

		echo malloc >  list_null_funcs_uniq;
		echo getenv >> list_null_funcs_uniq;
		cat $i | ./deference_check.pl |\
                     egrep -v 'x_trustfile.c ... ... sl_trustfile' | \
		     egrep -v 'x_sh_mem.c ';
		rm -f list_null_funcs_uniq;
		# rm -f $i
	    done
	) >test_log_smatch 2>&1
	if [ -f test_log_smatch ]; then
	    lines=`cat test_log_smatch | wc -l`
	    if [ $lines -ne 0 ]; then
		cat test_log_smatch
		rm -f test_log_smatch
		[ -z "$quiet" ] && log_fail $2 ${MAXTEST} "$TEST (smatch)";
		return 1
	    fi
	fi
	[ -z "$quiet" ] && log_ok $2 ${MAXTEST} "$TEST (smatch)";
	return 0
    fi
    [ -z "$quiet" ] && log_skip $2 ${MAXTEST} "$TEST (smatch)";
    return 0
}

testmake ()
{

	fail=0
	#
	# Compiler warnings can be OS specific, but at least
	# on Linux there should be none
	#
	isLinux=0
	uname -a | grep Linux >/dev/null
	if [ $? -eq 0 ]; then
	    isLinux=1
	    sed --in-place 's/-Wall/-Wall -Werror/' Makefile
	fi
	#
	if test x$1 = x0; then
		[ -z "$verbose" ]     ||  log_msg_ok  "configure...  $TEST";
		$MAKE clean > /dev/null 2>> test_log
		$MAKE ${SMATCH} cutest > /dev/null 2>> test_log
		if test x$? = x0; then
		    [ -z "$verbose" ] || log_msg_ok   "make cutest... $TEST";
 		else
		    [ -z "$quiet" ] &&   log_msg_fail "make cutest... $TEST";
		    fail=1
		fi
	else
		[ -z "$quiet" ] &&       log_msg_fail "configure...   $TEST";
	        if [ x"$3" = xskip ]; then
		    [ -z "$quiet" ] && log_skip $2 ${MAXTEST} "$TEST";
		fi
		fail=1
	fi
	if [ $isLinux -eq 1 ]; then
	    sed --in-place 's/-Wall -Werror/-Wall/' Makefile
	fi
	if [ $fail -eq 1 ]; then
	    [ -z "$quiet" ] && log_fail $2 ${MAXTEST} "$TEST";
	    return 1
	fi
	[ -z "$quiet" ] &&     log_ok   $2 ${MAXTEST} "$TEST";
	return 0
}

testcompile ()
{
	log_start "COMPILE"

	if [ "x$doall" = xon ]; then
	    uname -a | grep x86_64 >/dev/null 
	    if [ $? -ne 0 ]; then
		if [ -f /usr/local/gcc-smatch/bin/gcc ]; then  # FIXME
		    SAVE_CC="${CC}"
		    SMATCH="DBGDEF=--smatch"; export SMATCH
		    SAVE_SMATCH="${SMATCH}"; export SAVE_SMATCH
		    CC="/usr/local/gcc-smatch/bin/gcc"; export CC
		    SMATCH_CC="${CC}"
		fi
	    fi
	fi

	num=0
	numfail=0

	
	C_LOGFILE=""

	ls /lib/libpcre* >/dev/null 2>&1
	if [ $? -eq 0 ]; then
	    C_LOGFILE=" --enable-logfile-monitor "
	else
	    ls /usr/lib/libpcre* >/dev/null 2>&1
	    if [ $? -eq 0 ]; then
		C_LOGFILE=" --enable-logfile-monitor "
	    else
		ls /usr/lib/*/libpcre* >/dev/null 2>&1
		if [ $? -eq 0 ]; then
		    C_LOGFILE=" --enable-logfile-monitor "
		else
		    ls /usr/local/lib/libpcre* >/dev/null 2>&1
		    if [ $? -eq 0 ]; then
			C_LOGFILE=" --enable-logfile-monitor "
		    fi
		fi
	    fi
	fi
	if [ x"${C_LOGFILE}" = x ]; then
	    log_msg_ok  "Not testing  --enable-logfile-monitor";
	fi

	#
	# test dnmalloc
	#
        TEST="${S}check dnmalloc${E}"
	#
	${TOP_SRCDIR}/configure --quiet > /dev/null 2>> test_log
	#
	let "num = num + 1" >/dev/null
	#
	run_dnmalloc 0 $num || let "numfail = numfail + 1"  >/dev/null
	#

	#
	# test flawfinder
	#
        TEST="${S}check w/flawfinder${E}"
	#
	#
	let "num = num + 1" >/dev/null
	FLAWFINDER=`find_path flawfinder`
	#
	if [ -z "$FLAWFINDER" ]; then
	    log_skip $num $MAXTEST 'check w/flawfinder (not in PATH)'
	else
	    run_flawfinder 0 $num || let "numfail = numfail + 1"  >/dev/null
	fi
	#

	#
	# test standalone compilation
	#
        TEST="${S}standalone w/suidcheck w/procchk${E}"
	#
	if test -r "Makefile"; then
		$MAKE distclean 
	fi
	#
	${TOP_SRCDIR}/configure --quiet  --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test  --enable-suidcheck --enable-process-check > /dev/null 2>> test_log
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	#
	# test standalone compilation
	#
        TEST="${S}standalone static w/suidcheck w/procchk${E}"
	#
	if test -r "Makefile"; then
		$MAKE distclean 
	fi
	#
	[ -z "${SMATCH}" ] || { CC="${SAVE_CC}"; export CC; SMATCH=""; export SMATCH; }
	#
	${TOP_SRCDIR}/configure --quiet  --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test  --enable-static --enable-suidcheck --enable-process-check ${C_LOGFILE} > /dev/null 2>> test_log
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null
	#
	[ -z "${SMATCH_CC}" ] || { CC="${SMATCH_CC}"; export CC; SMATCH="${SAVE_SMATCH}"; export SMATCH; }
	#
	# test standalone compilation
	#
        TEST="${S}standalone w/procchk w/portchk${E}"
	#
	if test -r "Makefile"; then
		$MAKE distclean 
	fi
	#
	${TOP_SRCDIR}/configure --quiet  --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test  --enable-process-check --enable-port-check > /dev/null 2>> test_log
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	#
	# test standalone compilation
	#
        TEST="${S}standalone w/procchk w/portchk w/static${E}"
	#
	if test -r "Makefile"; then
		$MAKE distclean 
	fi
	#
	[ -z "${SMATCH}" ] || { CC="${SAVE_CC}"; export CC; SMATCH=""; export SMATCH; }
	#
	${TOP_SRCDIR}/configure --quiet  --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test  --enable-process-check --enable-port-check --enable-static > /dev/null 2>> test_log
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null
	#
	[ -z "${SMATCH_CC}" ] || { CC="${SMATCH_CC}"; export CC; SMATCH="${SAVE_SMATCH}"; export SMATCH; }
	#
	# test standalone compilation
	#
        TEST="${S}standalone w/procchk w/portchk w/stealth${E}"
	#
	if test -r "Makefile"; then
		$MAKE distclean 
	fi
	#
	${TOP_SRCDIR}/configure --quiet  --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test  --enable-stealth=164 --enable-process-check --enable-port-check > /dev/null 2>> test_log
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	#
	# test standalone compilation
	#
        TEST="${S}standalone w/mounts-check w/userfiles${E}"
	#
	if test -r "Makefile"; then
		$MAKE distclean 
	fi
	#
	${TOP_SRCDIR}/configure --quiet  --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test  --enable-mounts-check --enable-userfiles  > /dev/null 2>> test_log
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null


	#
	# test standalone compilation
	#
        TEST="${S}standalone w/timeserver and w/msgqueue${E}"
	#
	if test -r "Makefile"; then
		$MAKE clean 
	fi
	#
	${TOP_SRCDIR}/configure --quiet  --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test  --enable-message-queue --with-timeserver=127.0.0.1 > /dev/null 2>> test_log
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	#
	# test standalone compilation with --with-nocl=PW
	#
	TEST="${S}standalone w/nocl w/logmon${E}"
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet  --prefix=$PW_DIR --enable-nocl="owl" --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test ${C_LOGFILE} > /dev/null 2>> test_log   
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	#
	# test standalone compilation w/ debug
	#
	TEST="${S}standalone w/debug${E}"
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-debug  --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test  > /dev/null 2>> test_log  
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num debug || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	#
	# test standalone compilation w/ gpg
	#
	TEST="${S}standalone w/gpg${E}"
	#
	GPG=`find_path gpg`
	let "num = num + 1" >/dev/null
	#
	if [ -z "$GPG" ]; then
	    log_skip $num $MAXTEST 'gpg not in PATH'
            let "num = num + 1" >/dev/null
	    log_skip $num $MAXTEST 'gpg not in PATH'
	else
	    if test -r "Makefile"; then
		$MAKE clean
	    fi
	    #
	    ${TOP_SRCDIR}/configure --quiet --with-gpg=$GPG  --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test > /dev/null 2>> test_log   
	    #
	    testmake $? $num || let "numfail = numfail + 1" >/dev/null
	    let "num = num + 1" >/dev/null
	    run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	    let "num = num + 1" >/dev/null
	    run_uno $? $num || let "numfail = numfail + 1"  >/dev/null
	fi

	#
	# test standalone compilation w/stealth
	#
	TEST="${S}standalone w/stealth${E}"
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-stealth=128 --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test > /dev/null 2>> test_log   
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	#
	# test standalone compilation w/loginwatch
	#
	TEST="${S}standalone w/login-watch${E}"
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-login-watch  --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test > /dev/null 2>> test_log   
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	#
	# test standalone compilation w/mysql
	#
	TEST="${S}standalone w/mysql${E}"
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-xml-log --with-database=mysql  --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test > /dev/null 2>> test_log
	#
	let "num = num + 1" >/dev/null
	testmake $? $num "skip" || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	#
	# test standalone compilation w/mysql and stealth
	#
	TEST="${S}standalone w/mysql+stealth${E}"
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-xml-log --enable-stealth=128 --with-database=mysql  --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test > /dev/null 2>> test_log
	#
	let "num = num + 1" >/dev/null
	testmake $? $num "skip" || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	#
	# test standalone compilation w/postgresql
	#
	TEST="${S}standalone w/postgresql${E}"
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-xml-log --with-database=postgresql  --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test > /dev/null 2>> test_log
	#
	let "num = num + 1" >/dev/null
	testmake $? $num "skip" || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	#
	# test standalone compilation w/postgresql+stealth
	#
	TEST="${S}standalone w/postgresql+stealth${E}"
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-xml-log --enable-stealth=128 --with-database=postgresql  --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test > /dev/null 2>> test_log
	#
	let "num = num + 1" >/dev/null
	testmake $? $num "skip" || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	#
	# test standalone compilation
	#
	TEST="${S}standalone w/o mail w/unix_rnd${E}"
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --disable-mail --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test --with-rnd=unix > /dev/null 2>> test_log  
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	#
	# test standalone compilation
	#
	TEST="${S}standalone w/o external${E}"
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --disable-external-scripts --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test > /dev/null 2>> test_log   
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	# echo; echo "${S}__ TEST CLIENT/SERVER __${E}"; echo;

	#
	# test client/server compilation
	#
	TEST="${S}client/server application w/timeserver${E}"
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-network=client  --enable-srp --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test   --with-timeserver=127.0.0.1 > /dev/null 2>> test_log   
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null
	
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-network=server  --enable-srp --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test   --with-timeserver=127.0.0.1 > /dev/null 2>> test_log   
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	#
	# test client/server compilation w/prelude
	#
	TEST="${S}client/server application w/prelude${E}"
	#
	if [ -z "$doall" ]; then
	    let "num = num + 1" >/dev/null
	    [ -z "$quiet" ] && log_skip $num ${MAXTEST} "$TEST";
	    let "num = num + 1" >/dev/null
	    [ -z "$quiet" ] && log_skip $num ${MAXTEST} "$TEST (smatch)";
	    let "num = num + 1" >/dev/null
	    [ -z "$quiet" ] && log_skip $num ${MAXTEST} "$TEST (uno)";

	    let "num = num + 1" >/dev/null
	    [ -z "$quiet" ] && log_skip $num ${MAXTEST} "$TEST";
	    let "num = num + 1" >/dev/null
	    [ -z "$quiet" ] && log_skip $num ${MAXTEST} "$TEST (smatch)";
	    let "num = num + 1" >/dev/null
	    [ -z "$quiet" ] && log_skip $num ${MAXTEST} "$TEST (uno)";
	else
	    if test -r "Makefile"; then
		$MAKE clean
	    fi
	    #
	    ${TOP_SRCDIR}/configure --quiet --enable-network=client  --enable-srp --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test   --with-prelude > /dev/null 2>> test_log   
	    #
	    let "num = num + 1" >/dev/null
	    testmake $? $num || let "numfail = numfail + 1" >/dev/null
	    let "num = num + 1" >/dev/null
	    run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	    let "num = num + 1" >/dev/null
	    run_uno $? $num || let "numfail = numfail + 1"  >/dev/null
	    
	    if test -r "Makefile"; then
		$MAKE clean
	    fi
	    #
	    ${TOP_SRCDIR}/configure --quiet --enable-network=server  --enable-srp --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test   --with-prelude > /dev/null 2>> test_log   
	    #
	    let "num = num + 1" >/dev/null
	    testmake $? $num || let "numfail = numfail + 1" >/dev/null
	    let "num = num + 1" >/dev/null
	    run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	    let "num = num + 1" >/dev/null
	    run_uno $? $num || let "numfail = numfail + 1"  >/dev/null
	    #
	fi

	#
	# test client/server compilation
	#
	TEST="${S}client/server application static w/timeserver${E}"
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	[ -z "${SMATCH}" ] || { CC="${SAVE_CC}"; export CC; SMATCH=""; export SMATCH; }
	#
	${TOP_SRCDIR}/configure --quiet --enable-network=client  --enable-static --enable-srp --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test   --with-timeserver=127.0.0.1 ${C_LOGFILE} > /dev/null 2>> test_log   
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null
	
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-network=server  --enable-static --enable-srp --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test   --with-timeserver=127.0.0.1 > /dev/null 2>> test_log   
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null
	#
	[ -z "${SMATCH_CC}" ] || { CC="${SMATCH_CC}"; export CC; SMATCH="${SAVE_SMATCH}"; export SMATCH; }
	#
	# test c/s compilation w/ gpg
	#
	TEST="${S}client/server application w/gpg${E}"
	#
	GPG=`find_path gpg`
	let "num = num + 1" >/dev/null
	#
	if [ -z "$GPG" ]; then
	    log_skip $num $MAXTEST 'gpg not in PATH'
	    let "num = num + 1" >/dev/null
	    log_skip $num $MAXTEST 'gpg not in PATH'
	    let "num = num + 1" >/dev/null
	    log_skip $num $MAXTEST 'gpg not in PATH'
	    let "num = num + 1" >/dev/null
	    log_skip $num $MAXTEST 'gpg not in PATH'
	else
	    if test -r "Makefile"; then
		$MAKE clean
	    fi
	    #
	    ${TOP_SRCDIR}/configure --quiet --enable-network=server  --enable-srp --with-gpg=$GPG  --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test > /dev/null 2>> test_log   
	    #
	    testmake $? $num || let "numfail = numfail + 1" >/dev/null
	    let "num = num + 1" >/dev/null
	    run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	    let "num = num + 1" >/dev/null
	    run_uno $? $num || let "numfail = numfail + 1"  >/dev/null
	    #
	    if test -r "Makefile"; then
		$MAKE clean
	    fi
	    #
	    ${TOP_SRCDIR}/configure --quiet --enable-network=client  --enable-srp --with-gpg=$GPG  --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test ${C_LOGFILE} > /dev/null 2>> test_log   
	    #
	    let "num = num + 1" >/dev/null
	    testmake $? $num || let "numfail = numfail + 1" >/dev/null
	    let "num = num + 1" >/dev/null
	    run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	    let "num = num + 1" >/dev/null
	    run_uno $? $num || let "numfail = numfail + 1"  >/dev/null
	fi


	#
	# test client/server compilation
	#
	TEST="${S}client/server application w/o srp, w/udp${E}"
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-network=server --enable-udp --disable-srp --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test > /dev/null 2>> test_log   
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-network=client --disable-srp --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test > /dev/null 2>> test_log   
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	#
	# test client/server compilation w/ debug
	#
	TEST="${S}client/server application w/debug${E}"
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-network=server --enable-debug --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test > /dev/null 2>> test_log   
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num debug || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-network=client --enable-debug --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test ${C_LOGFILE} > /dev/null 2>> test_log   
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num debug || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	#
	# test client/server compilation w/stealth
	#
	TEST="${S}client/server application w/stealth${E}"
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-network=server  --enable-srp --enable-stealth=128 --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test  > /dev/null 2>> test_log  
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-network=client  --enable-srp --enable-stealth=128 --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test  > /dev/null 2>> test_log  
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	#
	# test  client/server compilation w/logwatch
	#
	TEST="${S}client/server application w/login-watch,udp,no_ipv6${E}"
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-network=server  --enable-udp --disable-ipv6 --enable-srp --enable-login-watch --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test  > /dev/null 2>> test_log  
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-network=client  --disable-ipv6 --enable-srp --enable-login-watch --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test  > /dev/null 2>> test_log  
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	#
	# test client/server compilation
	#
	TEST="${S}client/server application w/o mail${E}"
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-network=server  --disable-mail --enable-srp --enable-stealth=128 --enable-debug --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test > /dev/null 2>> test_log   
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num debug || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-network=client  --disable-mail --enable-srp --enable-stealth=128 --enable-debug --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test > /dev/null 2>> test_log   
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num debug || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	#
	# test client/server compilation
	#
	TEST="${S}client/server application w/o external${E}"
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-network=server  --disable-srp --disable-external-scripts --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test > /dev/null 2>> test_log   
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null
	#
	if test -r "Makefile"; then
		$MAKE clean
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-network=client  --disable-srp --disable-external-scripts --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/samhainrc.test > /dev/null 2>> test_log   
	#
	let "num = num + 1" >/dev/null
	testmake $? $num || let "numfail = numfail + 1" >/dev/null
	let "num = num + 1" >/dev/null
	run_smatch $? $num || let "numfail = numfail + 1"  >/dev/null
	let "num = num + 1" >/dev/null
	run_uno $? $num || let "numfail = numfail + 1"  >/dev/null

	[ -z "${SMATCH}" ] || { CC="${SAVE_CC}"; export CC; }

	log_end "COMPILE"
}

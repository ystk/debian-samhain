#! /bin/sh

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


# -----------------------------------------------------------------------
# The default configuration file
# -----------------------------------------------------------------------

cfgfile="/etc/samhainrc"

# -----------------------------------------------------------------------
# Be Bourne compatible
# -----------------------------------------------------------------------

if test -n "${ZSH_VERSION+set}" && (emulate sh) >/dev/null 2>&1; then
  emulate sh
  NULLCMD=:
elif test -n "${BASH_VERSION+set}" && (set -o posix) >/dev/null 2>&1; then
  set -o posix
fi

programname="$0"
sysmap=

# -----------------------------------------------------------------------
# Print help
# -----------------------------------------------------------------------

showhelp() {
    echo
    echo "$programname - update samhain config file after kernel update"
    echo
    echo "OPTIONS:"
    echo
    echo " -u|--update </path/to/System.map>"
    echo "         Update the configuration file with new"
    echo "         settings as taken from </path/to/System.map>"
    echo
    echo " -c|--config-file </path/to/config-file>"
    echo "         Specify the configuration file to update [${cfgfile}]"
    echo
    echo " -p|--print-only </path/to/System.map>"
    echo "         Print new settings, don't modify anything"
    echo
    echo " -h|--help"
    echo "         Print this help"
    echo
    echo " -n|--nocolor"
    echo "         (ignored, legacy support)"
    echo
}


# -----------------------------------------------------------------------
# Death strikes
# -----------------------------------------------------------------------

die() {
    echo ${1+"$@"} >&2
    { (exit 1); exit 1; }
}

# -----------------------------------------------------------------------
# Get new settings from </path/to/System.map>
# -----------------------------------------------------------------------

system_call=
syscall_table=
proc_root=
proc_root_inode_operations=
proc_root_lookup=

get_new_settings() {

    if [ -z "$sysmap" ]; then
	die "No System.map specified"
    fi
    if [ -f "$sysmap" ]; then
	if [ -r "$sysmap" ]; then
	    system_call=`egrep '[[:alnum:]]{8}[[:space:]]+[[:alpha:]]{1}[[:space:]]+system_call$' ${sysmap} | awk '{ print $1 }'`
	    syscall_table=`egrep '[[:alnum:]]{8}[[:space:]]+[[:alpha:]]{1}[[:space:]]+sys_call_table$' ${sysmap} | awk '{ print $1 }'`
	    proc_root=`egrep '[[:alnum:]]{8}[[:space:]]+[[:alpha:]]{1}[[:space:]]+proc_root$' ${sysmap} | awk '{ print $1 }'`
	    proc_root_inode_operations=`egrep '[[:alnum:]]{8}[[:space:]]+[[:alpha:]]{1}[[:space:]]+proc_root_inode_operations$' ${sysmap} | awk '{ print $1 }'`
	    proc_root_lookup=`egrep '[[:alnum:]]{8}[[:space:]]+[[:alpha:]]{1}[[:space:]]+proc_root_lookup$' ${sysmap} | awk '{ print $1 }'`
	else
	    die "System.map ${sysmap} not readable"
	fi
    else
	die "System.map ${sysmap} not found"
    fi
    test -z "${system_call}" && die "system_call not found in ${cfgfile}"
    test -z "${syscall_table}" && die "sys_call_table not found in ${cfgfile}"
    test -z "${proc_root}" && die "proc_root not found in ${cfgfile}"
    test -z "${proc_root_inode_operations}" && die "proc_root_inode_operations not found in ${cfgfile}"
    test -z "${proc_root_lookup}" && die "proc_root_lookup not found in ${cfgfile}"

}

# -----------------------------------------------------------------------
# Print new settings
# -----------------------------------------------------------------------

run_print() {
    get_new_settings
    echo
    echo "KernelSystemCall =     0x${system_call}"
    echo "KernelSyscallTable =   0x${syscall_table}"
    echo "KernelProcRoot =       0x${proc_root}"
    echo "KernelProcRootIops =   0x${proc_root_inode_operations}"
    echo "KernelProcRootLookup = 0x${proc_root_lookup}"
    echo
}

# -----------------------------------------------------------------------
# Replace a setting
# -----------------------------------------------------------------------

# set ignorecase
# search pattern
# delete current line
# insert
# single dot == end of insert text
# save and exit

run_replace() {
    item="$1"
    address="$2"
    ex -s "$cfgfile" <<EOF
:set ic
:/^[[:blank:]]*$1[[:blank:]]*=
:d
:i
$item = $address
.
:x
EOF
}

# -----------------------------------------------------------------------
# Add a setting
# -----------------------------------------------------------------------

# set ignorecase
# search pattern ([Kernel] section)
# append (next line)
# single dot == end of insert text
# save and exit

run_add() {
    item="$1"
    address="$2"
    ex -s "$cfgfile" <<EOF
:set ic
:/^[[:space:]]*\[Kernel\]
:a
$item = $address
.
:x
EOF
}

# -----------------------------------------------------------------------
# Update with new settings
# -----------------------------------------------------------------------

run_update() {

    get_new_settings

    if [ -z "$cfgfile" ]; then
	die "No configuration file specified"
    fi
    if [ ! -w "$cfgfile" ]; then
	die "Configuration file ${cfgfile} not writeable"
    fi
    egrep '^[[:space:]]*\[Kernel\]' "$cfgfile" >/dev/null
    if [ $? -ne 0 ]; then
	die "No [Kernel] section in configuration file $cfgfile"
    fi

    cat "$cfgfile" | egrep -i 'KernelProcRootLookup' >/dev/null
    if [ $? -eq 0 ]; then
	run_replace 'KernelProcRootLookup' "0x${proc_root_lookup}"
    else
	run_add 'KernelProcRootLookup' "0x${proc_root_lookup}"
    fi
 
    cat "$cfgfile" | egrep -i 'KernelProcRootIops' >/dev/null
    if [ $? -eq 0 ]; then
	run_replace 'KernelProcRootIops' "0x${proc_root_inode_operations}"
    else
	run_add 'KernelProcRootIops' "0x${proc_root_inode_operations}"
    fi

    cat "$cfgfile" | egrep -i 'KernelProcRoot[[:space:]]*=' >/dev/null
    if [ $? -eq 0 ]; then
	run_replace 'KernelProcRoot' "0x${proc_root}"
    else
	run_add 'KernelProcRoot' "0x${proc_root}"
    fi

    cat "$cfgfile" | egrep -i 'KernelSyscallTable' >/dev/null
    if [ $? -eq 0 ]; then
	run_replace 'KernelSyscallTable' "0x${syscall_table}"
    else
	run_add 'KernelSyscallTable' "0x${syscall_table}"
    fi

    cat "$cfgfile" | egrep -i 'KernelSystemCall' >/dev/null
    if [ $? -eq 0 ]; then
	run_replace 'KernelSystemCall' "0x${system_call}"
    else
	run_add 'KernelSystemCall' "0x${system_call}"
    fi

}

# -----------------------------------------------------------------------
# Parse command line
# -----------------------------------------------------------------------

sysmap=
action=

for option
do

  # If the previous option needs an argument, assign it.
  #
  if test -n "$opt_prev"; then
    eval "$opt_prev=\$option"
    eval export "$opt_prev"
    opt_prev=
    continue
  fi

  case "$option" in
      -*=*) 
	  optarg=`echo "$option" | sed 's/[-_a-zA-Z0-9]*=//'` 
	  ;;
      *) 
	  optarg= 
	  ;;
  esac

  case "$option" in

      -h|--help)
	  showhelp
	  exit 0
	  ;;

      -n|--nocolor)
	  ;;

      -c|--config-file)
	  opt_prev=cfgfile
	  ;;

      -c=* | --config-file=*)
	  cfgfile="$optarg"
	  ;;

      -p|--print-only)
	  opt_prev=sysmap
	  action=p
	  ;;


      -p=* | --print-only=*)
	  sysmap="$optarg"
	  action=p
	  ;;
    
      -u|--update)
	  opt_prev=sysmap
	  action=u
	  ;;

      -u=* | --update=*)
	  sysmap="$optarg"
	  action=u
	  ;;

  esac

done

if [ x"$action" = xp ]; then
    run_print
    exit 0
fi
if [ x"$action" = xu ]; then
    run_update
    exit 0
fi

showhelp
exit 1

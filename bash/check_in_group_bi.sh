#!/bin/bash
# bi == Broker Interface
# Script should be at /usr/sbin, like /usr/sbin/check_in_group_bi.sh and added to sudoers.
# Example of usage: check_in_group_bi.sh -u -g vdi-broker-users

read_arguments(){
  # read user passed arguments
  USAGE="$(basename "$0") -u existing_user1, --username user1  -g existing_group, --group existing_group [-h, --help]"

  UNKNOWN=()
  USERNAME=""
  GROUPNAME=""

  while [[ $# -gt 0 ]]
  do
    KEY="$1"
    case ${KEY} in
        -u|--username)
        USERNAME="$2"
        shift # past argument
        shift # past value
        ;;
        -g|--group)
        GROUPNAME="$2"
        shift # past argument
        shift # past value
        ;;
        -h|--help)
        echo "${USAGE}"
        exit 0
        ;;
        *)    # unknown option
          UNKNOWN+=("$1") # save it in an array for later
        shift # past argument
        ;;
    esac
  done
  if [ -n "${UNKNOWN}" ]; then
    echo "${USAGE}"
    print_arguments
    echo "Unknown arguments: ${UNKNOWN}" >&2
    exit 1
  fi

  if [ -z "${USERNAME}" ]; then
    echo "Username can't be empty." >&2
    exit 1
  fi

  if [ -z "${GROUPNAME}" ]; then
    echo "Groupname can't be empty." >&2
    exit 1
  fi

}

print_arguments(){
  echo "user argument is: <<${USERNAME}>>"
  echo "group argument is: <<${GROUPNAME}>>"
}

build_command(){
  SUDO_PATH="/usr/bin/sudo"
  ID_COMMAND="/usr/bin/id -Gn ${USERNAME}"
  GREP_COMMAND="grep -c ${GROUPNAME}"
  FULL_COMMAND="${SUDO_PATH} ${ID_COMMAND} | ${GREP_COMMAND}"
}

execute_command(){
  eval "${FULL_COMMAND}"
  exit 0
}

read_arguments "$@"

build_command

execute_command

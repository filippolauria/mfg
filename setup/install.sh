#!/bin/bash

#
# Input helpers
#

# usage: get_port "text" "default"
get_port() {
  while true; do
    PORT=""
    
    read -r -p "[>] $1 [$2]: " PORT
    if [ -z "$PORT" ]; then
      PORT="$2"
      break
    fi

    if [ "$PORT" -ge 1 ] && [ "$PORT" -le 65534 ]; then
      break
    fi
    
    echo "[!] The value must be chosen between 1024 and 65534"
    
  done
}

# usage: get_string "text" "default"
get_string() {
  S=""
  
  while true; do
    LABEL="$1"
    if [ ! -z "$2" ]; then
      LABEL="${LABEL} [$2]: "
    fi
  
    read -r -p "[>] $LABEL: " S
    if [ ! -z "$S" ]; then
      break
    fi
    
    if [ ! -z "$2" ]; then
      S="$2"
      break
    fi
    
  done
  
  printf "%s" "$S"
}

#usage: get_password "text1" "text2"
get_password() {
  while true; do
    PASS1=""
    PASS2=""
    
    while [ -z "$PASS1" ]; do
      printf "[>] %s: " "$1"
      read -r -s PASS1
      echo ""
    done
    
    while [ -z "$PASS2" ]; do
      printf "[>] %s: " "$2"
      read -r -s PASS2
      echo ""
    done
    
    if [ "$PASS1" == "$PASS2" ]; then
      break
    fi
    
    echo "[!] Passwords don't match"
  done

}


APP_SHORTNAME="MFG"

# we check that the script is running as root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run this script as root"
  exit 1
fi

# we get the host operating system
OS=$(grep '^ID=' /etc/*-release | cut -d'=' -f2)
case $OS in
  "ubuntu"|"debian")
    echo "[+] Good! ${APP_SHORTNAME} can be installed on ${OS}."
    if ! apt -f update; then echo "[!] Error when updating package information."; exit 1; fi

    ;;
  *)
    echo "[!] We are sorry. ${APP_SHORTNAME} installation procedure has not been tested on ${OS}."
    exit 1
    ;;
esac

# we get the path of this script
pushd . > /dev/null
SCRIPT_PATH="${BASH_SOURCE[0]}"
if ([ -h "${SCRIPT_PATH}" ]); then
  while([ -h "${SCRIPT_PATH}" ]); do cd "$(dirname "$SCRIPT_PATH")" || continue;
  SCRIPT_PATH=$(readlink "${SCRIPT_PATH}"); done
fi
cd "$(dirname "${SCRIPT_PATH}")" || exit 0
SCRIPT_PATH=$(pwd);
popd > /dev/null

# we get the absolute path of the installation directory
INSTALLATION_DIR=$(dirname "$SCRIPT_PATH")
echo "[+] We are going to install ${APP_SHORTNAME} in ${INSTALLATION_DIR}..."

# we check if an old configuration is present
CONFIG_FILE="${INSTALLATION_DIR}/config.json"
if [ -f "$CONFIG_FILE" ]; then
  echo "[!] ${CONFIG_FILE} will be removed."
  printf "[?] Are you sure you want to continue? [Y/n] "
  read -r CONTINUE
  case $CONTINUE in
    N|n) echo "[+] Installation aborted"; exit 0 ;;
  esac

  # rm -f "${CONFIG_FILE}"
fi

# get DB information
while true; do
  DB_HOST=""
  DB_PORT=""
  DB_USER=""
  DB_PASS=""
  DB_SCHEMA=""

  DB_HOST="$(get_string 'Insert a valid MariaDB/MySQL database address')"

  get_port 'Insert a valid MariaDB/MySQL Database port number' '3306'
  DB_PORT="$PORT"

  DB_SCHEMA="$(get_string 'Insert the name of the database schema to use' 'radius')"
  DB_USER="$(get_string 'Insert the MariaDB/MySQL username')"

  get_password 'Insert the MariaDB/MySQL password' 'Insert the MariaDB/MySQL password confirmation'
  DB_PASS="$PASS1"
  
  printf "[?] Do you want to test db connection? [Y/n] "
  read -r CONTINUE
  case $CONTINUE in
    N|n) break
  esac

  MYSQL_CLIENT="$(which mysql || command -v mysql)"

  if [ -z "$MYSQL_CLIENT" ]; then
    printf "[?] MariaDB/MySQL client command is needed. Do you want to install it? [Y/n] "
    read -r CONTINUE
    case $CONTINUE in
      N|n) break
    esac
    apt update && apt -y install mariadb-client
  fi

  MYSQL_CLIENT_FILENAME="$(mktemp -qu).conf"
  cat << EOF > "${MYSQL_CLIENT_FILENAME}"
[client]
database=${DB_SCHEMA}
host=${DB_HOST}
port=${DB_PORT}
user=${DB_USER}
password=${DB_PASS}
EOF

  if mysql --defaults-extra-file="${MYSQL_CLIENT_FILENAME}" --execute=";" 2> /dev/null; then
    echo "[!] Successfully connected to database."
    rm -rf "${MYSQL_CLIENT_FILENAME}"
    break
  fi

  rm -rf "${MYSQL_CLIENT_FILENAME}"
  echo "[!] Cannot connect to database."
  printf "[?] Do you want to retype in all the configurations? [Y/n] "
  read -r CONTINUE
  case $CONTINUE in
    N|n) break
  esac

done

# gen. key
K=$(python3 -c 'from random import SystemRandom; from string import ascii_letters,digits; print("".join(SystemRandom().choice(ascii_letters + digits) for _ in range(64)))')

# get SMTP information
MAIL_HOST=""
MAIL_PORT=""
MAIL_USER=""
MAIL_PASS=""

MAIL_HOST="$(get_string 'Insert a valid SMTP address')"

get_port 'Insert a valid SMTP port number' '465'
MAIL_PORT="$PORT"

MAIL_USER="$(get_string 'Insert the username to use for sending emails')"

get_password 'Insert the password related to the username you just entered' 'Confirm the password'
MAIL_PASS="$PASS1"

printf "[?] Do you want to use TLS? [Y/n] "
read -r USE_TLS
case $USE_TLS in
  N|n) USE_TLS="false" ;;
  *) USE_TLS="true" ;;
esac

printf "[?] Do you want to use SSL? [Y/n] "
read -r USE_SSL
case $USE_SSL in
  N|n) USE_SSL="false" ;;
  *) USE_SSL="true" ;;
esac

cat <<EOF
{
    "MFG_ACCOUNT_DISABLED_GROUPNAME": "Account Disabled",
    "MFG_PASSWORD_EXPIRED_GROUPNAME": "Password Expired",
    "MFG_DATABASE_TABLE_PREFIX": "mfg_",
    "SECRET_KEY": "${K}",
    "SQLALCHEMY_DATABASE_URI": "mysql://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_SCHEMA}",
    "SQLALCHEMY_TRACK_MODIFICATIONS": false,
    "MAIL_USERNAME": "${MAIL_USER}",
    "MAIL_PASSWORD": "${MAIL_PASS}",
    "MAIL_SERVER": "${MAIL_HOST}",
    "MAIL_PORT": ${MAIL_PORT},
    "MAIL_USE_TLS": ${USE_TLS},
    "MAIL_USE_SSL": ${USE_SSL}
}
EOF

# set up default dictionary symbolic link
LISTS_DIR="${INSTALLATION_DIR}/resources/lists"
ln -s "${LISTS_DIR}/dict-english.txt" "${LISTS_DIR}/dict.txt"

exit 0

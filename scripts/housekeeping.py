# -*- coding: utf-8 -*-
#
#  scripts/housekeeping.py
#
# Copyright 2021 Filippo Maria LAURIA <filippo.lauria@iit.cnr.it>
#
# Computer and Communication Networks (CCN)
# Institute of Informatics and Telematics (IIT)
# Italian National Council of Research (CNR)
#
#
# This file is part of the Minimal FreeRADIUS GUI (MFG).
#
# The Minimal FreeRADIUS GUI (MFG) is free software: you can redistribute
# it and/or modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# The Minimal FreeRADIUS GUI (MFG) is distributed in the hope that it will
# be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Minimal FreeRADIUS GUI (MFG).
# If not, see <http://www.gnu.org/licenses/>.
#


import os
import json
import sys
import mysql.connector
from urllib.parse import urlparse

basedir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
config_json = os.path.join(basedir, 'config.json')

# we check if the config.json file exists and is readable
if not (os.path.isfile(config_json) and os.access(config_json, os.R_OK)):
    print(f"[!] {config_json} does not exist or is not readable")
    sys.exit(-1)

# we load database uri string
with open(config_json, 'r') as fd:
    try:
        config = json.load(fd)
        db_uri = config['SQLALCHEMY_DATABASE_URI']
        table_prefix = config['MFG_DATABASE_TABLE_PREFIX']
        password_expired_groupname = config['MFG_PASSWORD_EXPIRED_GROUPNAME']
        account_disabled_groupname = config['MFG_ACCOUNT_DISABLED_GROUPNAME']
        if not db_uri.startswith("mysql"):
            print("[!] DATABASE_URI not specified or invalid")
            sys.exit(-1)

    except Exception:
        print(f"[!] {config_json} is not a valid json file")
        sys.exit(-1)

# parse the uri string
db = urlparse(db_uri)


# this function allows to select disabled accounts or accounts with an expired password
# and add them to the "account disabled" or "password expired" groups
def accounts_statuses_management(attribute, groupname):
    dbconn = mysql.connector.connect(host=db.hostname, port=db.port, user=db.username, passwd=db.password,
                                     database=db.path.strip("/"))
    dbcur = dbconn.cursor()

    user_table = table_prefix + 'user'

    sql = (
            f"SELECT `username` FROM `{user_table}` "
            f"WHERE CURDATE() > `{attribute}` "
            "AND `username` NOT IN (SELECT DISTINCT `username` FROM `radusergroup` WHERE `groupname` = %s)"
          )

    dbcur.execute(sql, (groupname, ))
    records = dbcur.fetchall()

    for username in records:
        sql = "INSERT INTO `radusergroup`(`username`, `groupname`, `priority`) VALUES(%s, %s, 1)"
        dbcur.execute(sql, (username, groupname, ))
        dbconn.commit()

    dbconn.close()


accounts_statuses_management('expires_on', password_expired_groupname)
accounts_statuses_management('disable_on', account_disabled_groupname)

# clean expired tokens
dbconn = mysql.connector.connect(host=db.hostname, port=db.port, user=db.username, passwd=db.password,
                                 database=db.path.strip("/"))
dbcur = dbconn.cursor()

for table in ['token', 'signup_token']:
    table = table_prefix + table
    sql = f"DELETE FROM `{table}` WHERE NOW() > `expires_on`"
    dbcur.execute(sql)
    dbconn.commit()

dbconn.close()

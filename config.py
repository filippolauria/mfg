# -*- coding: utf-8 -*-
#
#  config.py
#
# Copyright 2021 Filippo Maria LAURIA <filippo.lauria@iit.cnr.it>
#
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

# generate this with the command:
# python3 -c 'from random import SystemRandom; from string import ascii_letters,digits; '\
# 'print("".join(SystemRandom().choice(ascii_letters + digits) for _ in range(64)))'
secret_key = ''

# fill in with your db connection details
db_user = ''
db_pass = ''
db_host = 'localhost'
db_port = 3306

db_name = ''
table_prefix = 'mfg_'

account_disabled_groupname = 'Account Disabled'
password_expired_groupname = 'Password Expired'

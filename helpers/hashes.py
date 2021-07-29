# -*- coding: utf-8 -*-
#
#  helpers/hashes.py
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

import hashlib

# the list of the allowed hashing methods
allowed_hashing_methods = ['MD5-Password', 'SHA1-Password', 'Cleartext-Password']


def check_password_hash(password, hash_, hash_type):
    """
    this function takes a cleartext passwords and returns true if it matches with the passed hash_,
    hashed according the passed hash_type.
    If the hashed_type is not supported, it raises a ValueError exception
    """

    password = str(password)
    hash_ = str(hash_)

    if hash_type == 'Cleartext-Password':
        return password == hash_

    if hash_type == 'MD5-Password':
        h = str(hashlib.md5(password.encode()).hexdigest()).lower()
        hash_ = hash_.lower()
        return h == hash_

    if hash_type == 'SHA1-Password':
        h = str(hashlib.sha1(password.encode()).hexdigest()).lower()
        hash_ = hash_.lower()
        return h == hash_

    raise ValueError(f"Type {hash_type} not supported")


def make_hash(password, hash_type):
    """
    this function returns the hashed value (according to hash_type) associated with the passed password.
    If the hashed_type is not supported, it raises a ValueError exception
    """
    password = str(password)

    if hash_type == 'Cleartext-Password':
        return password

    if hash_type == 'MD5-Password':
        return str(hashlib.md5(password.encode()).hexdigest()).lower()

    if hash_type == 'SHA1-Password':
        return str(hashlib.sha1(password.encode()).hexdigest()).lower()

    raise ValueError(f"Type {hash_type} not supported")

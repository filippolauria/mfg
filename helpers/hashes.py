# -*- coding: utf-8 -*-
#
#  helpers/hashes.py
#
# Copyright 2022 Filippo Maria LAURIA <filippo.lauria@iit.cnr.it>
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

import hashlib
import binascii


class PasswordAttribute:
    def gen(self, plaintext):
        return str(plaintext)

    def __init__(self, plaintext):
        self.hash = self.gen(str(plaintext))

    def check(self, hash_):
        return self.hash == hash_

    def __str__(self):
        return self.hash


class CleartextPassword(PasswordAttribute):
    pass


class MD5Password(PasswordAttribute):
    def gen(self, plaintext):
        return str(hashlib.md5(plaintext.encode()).hexdigest()).upper()


class NTPassword(PasswordAttribute):
    def gen(self, plaintext):
        return str(binascii.hexlify(hashlib.new(
            'md4', plaintext.encode('utf-16le')).digest()).upper().decode())


class SHA1Password(PasswordAttribute):
    def gen(self, plaintext):
        return str(hashlib.sha1(plaintext.encode()).hexdigest()).upper()


# maps some password radius attributes to the correct function
allowed_hashing_methods_map = {
    'Cleartext-Password': CleartextPassword,
    'MD5-Password': MD5Password,
    'NT-Password':  NTPassword,
    'SHA1-Password': SHA1Password
}

# the list of the allowed hashing methods
allowed_hashing_methods = allowed_hashing_methods_map.keys()


class PasswordAttributeFactory:
    @classmethod
    def create(cls, plaintext, attribute):
        """ factory class for creating a (supported) password attribute"""

        if attribute not in allowed_hashing_methods:
            raise ValueError(f"Type {attribute} not supported")

        if attribute == 'Cleartext-Password':
            return CleartextPassword(plaintext)

        if attribute == 'MD5-Password':
            return MD5Password(plaintext)

        if attribute == 'NT-Password':
            return NTPassword(plaintext)

        if attribute == 'SHA1-Password':
            return SHA1Password(plaintext)


def check_password_hash(password, hash_, hash_type):
    """
    this function takes a cleartext passwords and returns true if it matches
    with the passed hash_, hashed according the passed hash_type.
    If the hashed_type is not supported, it raises a ValueError exception
    """

    hash_obj = PasswordAttributeFactory.create(password, hash_type)
    return hash_obj.check(hash_)


def make_hash(password, hash_type):
    """
    this function returns the hashed value (according to hash_type)
    associated with the passed password. If the hashed_type is not supported,
    it raises a ValueError exception
    """
    hash_obj = PasswordAttributeFactory.create(password, hash_type)
    return str(hash_obj)

# -*- coding: utf-8 -*-
#
#  helpers/utils.py
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

import random
import unidecode
from string import ascii_lowercase

from flask import flash


def make_token():
    """
    returns a random 32-chars string made of hex characters
    """
    return '%030x' % random.randrange(16**32)


def lowercase_filter_word(word):
    """
    replaces all the accented characters with their non accented equivalent, then strips all non-lowercase characters
    """
    return ''.join(filter(ascii_lowercase.__contains__, unidecode.unidecode(word)))


def flash_errors(form):
    """
    flashes form errors
    """
    for field, errors in form.errors.items():
        for error in errors:
            label = getattr(form, field).label.text
            flash(f'"{label}": {error}', 'danger')

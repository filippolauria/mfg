# -*- coding: utf-8 -*-
#
#  helpers/utils.py
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

import htmlmin
import os
import random
import unidecode
from random import SystemRandom
from string import ascii_lowercase
from flask import flash, current_app, render_template as flask_render_template


def render_template(template_path, **kwargs):
    output = flask_render_template(template_path, **kwargs)
    return str(htmlmin.minify(output, remove_comments=True, remove_empty_space=True, reduce_boolean_attributes=True))


def make_token():
    """
    returns a random 32-chars string made of hex characters
    """
    return '%030x' % SystemRandom().randrange(16**32)


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


def random_password():
    # we get the full path of the dictionary file
    dict_path = os.path.join(current_app.root_path, "resources", "lists", "dict.txt")

    # if it does not exist, we abort
    if not os.path.exists(dict_path):
        return False

    word1 = ""
    word2 = ""
    with open(dict_path, 'r') as fd:
        # we get two random words from the dictionary file
        words = [s.rstrip('\n') for s in fd.readlines()]

        # 1st word
        while True:
            word1 = random.choice(words)
            if word1 != "":
                break

        # 2nd word
        while True:
            word2 = random.choice(words)
            if word1 != word2 and word2 != "":
                break

    if word1 == "" or word2 == "":
        return False

    # pseudo-randomly transform word case
    transformed1 = ""
    for w in word1:
        transformed1 += w.lower() if random.randint(0, 1) else w.upper()

    transformed2 = ""
    for w in word2:
        transformed2 += w.lower() if random.randint(0, 1) else w.upper()

    # pseudo-randomly select a symbol
    symbols = "!#$%,-.:;@^_"
    symbol = random.choice(symbols)

    # pseudo-random number
    number = random.randint(0, 999)

    return f"{transformed1}{symbol}{transformed2}{number}"

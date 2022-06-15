# -*- coding: utf-8 -*-
#
#  helpers/decorators.py
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

from flask import abort, redirect, url_for
from flask_login import current_user
from functools import wraps


def is_admin(func):
    """
    decorator that redirects to the login page, if the current user is not authenticated,
    or aborts with the HTTP 403 status code, if the current_user is not an admin
    """

    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.is_admin:
                return func(*args, **kwargs)

            return abort(403)

        return redirect(url_for('auth.login'))

    return decorated_function


def is_admin_or_contact_person(func):
    """
    decorator that redirects to the login page, if the current user is not authenticated,
    or aborts with the HTTP 403 status code, if the current_user is not an admin or a contact person
    """

    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.is_admin or current_user.is_contact_person():
                return func(*args, **kwargs)

            return abort(403)

        return redirect(url_for('auth.login'))

    return decorated_function


def is_regular_user(func):
    """
    decorator that aborts with the HTTP 403 status code, if the current_user is an admin or a contact person
    """

    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            if not (current_user.is_admin or current_user.is_contact_person()):
                return func(*args, **kwargs)

            return abort(403)

        return redirect(url_for('auth.login'))

    return decorated_function


def is_authenticated(func):
    """
    decorator that redirects to the login page, if the current_user is not authenticated
    """
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            return func(*args, **kwargs)

        return redirect(url_for('auth.login'))

    return decorated_function

# -*- coding: utf-8 -*-
#
#  helpers/config.py
#
# Copyright 2022 Filippo Maria LAURIA <filippo.lauria@iit.cnr.it>
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

from mfg.models import GlobalSettings, OrganizationSettings
from mfg import db

# dictionary that holds default global setting value, type and description
default_global_settings = {
    'self.signup.method': {
        'value': '0', 'coerce': int,
        'desc': (
                  'If it is not 0, it allows users with email from a particular organization '
                  'to create an account for themselves.'
                )
    },
    'max.password.expired.after.days': {
        'value': '180', 'coerce': int,
        'desc': (
                  'Maximum number of days allowed before a password is considered expired. '
                  'Per-organization settings cannot exceed this upper bound.'
                )
    },
    'max.account.disabled.after.months': {
        'value': '36', 'coerce': int,
        'desc': (
                  'Maximum number of months allowed before an account is automatically disabled. '
                  'Per-organization settings cannot exceed this upper limit.'
                )
    },
    'max.token.expired.after.hours': {
        'value': '6', 'coerce': int,
        'desc': (
                  'Maximum number of hours allowed before a password recovery token is considered expired. '
                  'Per-organization settings cannot exceed this maximum limit.'
                )
    },
    'max.signup.token.expired.after.hours': {
        'value': '12', 'coerce': int,
        'desc': (
                  'Maximum number of hours allowed before a self-registration token is considered expired. '
                  'Per-organization settings cannot exceed this maximum limit.'
                )
    },
    'max.items.per.page': {
        'value': '50', 'coerce': int,
        'desc': (
                  'Maximum number of items allowed in the user table view. '
                  'Per-organization settings cannot exceed this maximum limit.'
                )
    },
    'alert.when.password.expires.in.days': {
        'value': '10', 'coerce': int,
        'desc': (
                  'Allows you to specify the number of days before the password expires '
                  'in which an alert is sent to the user.'
                )
    },
    'hashing.algorithm': {
        'value': 'NT-Password', 'coerce': str,
        'desc': 'Allows you to specify the hashing algorithm to be used for storing passwords.'
    },
    'application.name': {
        'value': 'Minimal FreeRADIUS GUI', 'coerce': str,
        'desc': 'Allows you to customize the name of this MFG instance.'
    },
    'application.shortname': {
        'value': 'MFG', 'coerce': str, 'desc': 'Allows you to customize the short-name of this MFG instance.'
    },
    'smtp.hostname': {
        'value': '', 'coerce': str,
        'desc': (
                  'Allows you to specify the IP address/domain name of the SMTP server '
                  'to be used for sending emails to users.'
                )
    },
    'smtp.port': {
        'value': '25', 'coerce': int,
        'desc': (
                  'Allows you to specify the TCP port number of the SMTP server '
                  'to be used for sending emails to users.'
                )
    },
    'smtp.username': {
        'value': '', 'coerce': str,
        'desc': (
                  'Allows you to specify the username to be used for logging in the SMTP server '
                  'to be used for sending emails to users.'
                )
    },
    'smtp.password': {
        'value': '', 'coerce': str,
        'desc': (
                  'Allows you to specify the password to be used for logging in the SMTP server '
                  'to be used for sending emails to users.'
                )
    },
    'smtp.email': {
        'value': '', 'coerce': str,
        'desc': 'Allows you to specify the email from which user alerts are sent.'
    },
}


# dictionary that holds per-organization setting default value and type
default_organization_settings = {
    # 0 disabled, 1 approval always required, 2 approval only when needed
    'self.signup.method': {
        'value': '0', 'coerce': int,
        'desc': (
                  'If you set this setting to 0, self-registration is not allowed for users with an email '
                  'from this organization. If you set it to 1, self-registration always ends with the approval '
                  'of an administrator or contact person. If you set it to 2, self-registration is completed with '
                  'the approval of an administrator or contact person only when necessary.'
                )
    },
    'password.expired.after.days': {
        'value': '180', 'coerce': int,
        'desc': 'The number of days before a password is considered expired.'
    },
    'account.disabled.after.months': {
        'value': '36', 'coerce': int,
        'desc': 'The number of months before an account is automatically disabled.'
    },
    'token.expired.after.hours': {
        'value': '6', 'coerce': int,
        'desc': 'The number of hours before a password recovery token is considered expired.'
    },
    'signup.token.expired.after.hours': {
        'value': '12', 'coerce': int,
        'desc': 'The number of hours before a self-registration token is considered expired.'
    },
    'items.per.page': {
        'value': '50', 'coerce': int,
        'desc': 'The number of items to display in the user table view.'
    },
}


class ConfigPropertyException(Exception):
    pass


class ConfigPropertyNotAllowed(ConfigPropertyException):
    pass


class ConfigPropertyNotFound(ConfigPropertyException):
    pass


class OrganizationNotFound(Exception):
    pass


class OrganizationConfigManager:
    """
    Class for managing per-organization settings
    """

    def __init__(self, organization):
        self.organization = organization

    def set_default(self):
        """
        this method populates the db with the default settings for a specific organization.
        """

        db.session.query(OrganizationSettings).delete()

        for k, d in default_organization_settings.items():
            v = d["coerce"](d["value"])
            new_property = OrganizationSettings(keyword=k, value=v)
            new_property.organization = self.organization
            db.session.add(new_property)

        db.session.commit()

    def get(self, property_name, return_default_if_not_found=True):
        """
        this method retrieves settings value from the db for a specific organization.
        If return_default_if_not_found is True, it returns the default contained in default_organization_settings,
        otherwise it raises a ConfigPropertyNotFound exception
        """

        if property_name not in default_global_settings.keys():
            raise ConfigPropertyNotAllowed

        property_obj = db.session.query(OrganizationSettings).filter(
                           (OrganizationSettings.organization == self.organization) &
                           (OrganizationSettings.keyword == property_name)).first()
        default_prop = default_global_settings[property_name]
        cast = default_prop["coerce"]
        if not property_obj:
            if return_default_if_not_found:
                return cast(default_prop["value"])

            raise ConfigPropertyNotFound

        return cast(property_obj.value)


class ConfigManager:

    @staticmethod
    def set_default():
        """
        this method populates the db with the global default settings.
        """

        db.session.query(GlobalSettings).delete()

        for k, d in default_global_settings.items():
            v = d["coerce"](d["value"])
            new_setting = GlobalSettings(keyword=k, value=v)
            db.session.add(new_setting)

        db.session.commit()

    @staticmethod
    def get(property_name, return_default_if_not_found=True):
        """
        this method retrieves a particular property from the globa settings stored in the db.
        If return_default_if_not_found is True, it returns the default contained in default_global_settings,
        otherwise it raises a ConfigPropertyNotFound exception
        """

        if property_name not in default_global_settings.keys():
            raise ConfigPropertyNotAllowed

        property_obj = db.session.query(GlobalSettings).filter(GlobalSettings.keyword == property_name).first()
        default_prop = default_global_settings[property_name]
        cast = default_prop["coerce"]
        if not property_obj:
            if return_default_if_not_found:
                return cast(default_prop["value"])

            raise ConfigPropertyNotFound

        return cast(property_obj.value)

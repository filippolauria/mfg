# -*- coding: utf-8 -*-
#
#  helpers/config.py
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

from mfg.models import GlobalSettings, OrganizationSettings
from mfg import db

# dictionary that holds global setting default value and type
default_global_settings = {
    "auto.signup.method": {"value": "0", "coerce": int},
    "max.password.expired.after.days": {"value": "180", "coerce": int},
    "max.account.disabled.after.months": {"value": "36", "coerce": int},
    "max.token.expired.after.hours": {"value": "6", "coerce": int},
    "max.signup.token.expired.after.hours": {"value": "12", "coerce": int},
    "max.items.per.page": {"value": "50", "coerce": int},
    "alert.when.password.expires.in.days": {"value": "10", "coerce": int},
    "hasing.algorithm": {"value": "MD5-Password", "coerce": str},
    "application.name": {"value": "Minimal FreeRADIUS GUI", "coerce": str},
    "application.shortname": {"value": "MFG", "coerce": str},
    "smtp.hostname": {"value": "", "coerce": str},
    "smtp.port": {"value": "25", "coerce": int},
    "smtp.username": {"value": "", "coerce": str},
    "smtp.password": {"value": "", "coerce": str},
    "smtp.email": {"value": "", "coerce": str},
}

# dictionary that holds per-organization setting default value and type
default_organization_settings = {
    # 0 disabled, 1 approval always required, 2 approval only when needed
    "auto.signup.method": {"value": "0", "coerce": int},
    "password.expired.after.days": {"value": "180", "coerce": int},
    "account.disabled.after.months": {"value": "36", "coerce": int},
    "token.expired.after.hours": {"value": "6", "coerce": int},
    "signup.token.expired.after.hours": {"value": "12", "coerce": int},
    "items.per.page": {"value": "50", "coerce": int},
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

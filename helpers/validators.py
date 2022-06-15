# -*- coding: utf-8 -*-
#
#  helpers/validators.py
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

from wtforms.validators import ValidationError, InputRequired, Length

from mfg import db
from mfg.models import User


class UserAlreadyExists(object):
    def __call__(self, form, field):
        if db.session.query(User).filter_by(username=field.data).first():
            raise ValidationError(f"{field.data} already exists")


class EmailAlreadyUsed(object):
    def __call__(self, form, field):
        user_obj = db.session.query(User).filter_by(email=field.data).first()
        if user_obj:
            raise ValidationError(f"{field.data} is already used by {user_obj.username}")


class IfChecked(InputRequired):
    def __init__(self, checkbox_field_name, required=True, *args, **kwargs):
        self.required = required
        self.checkbox_field_name = checkbox_field_name
        super(IfChecked, self).__init__(*args, **kwargs)

    def __call__(self, form, field):
        checkbox_field = form._fields.get(self.checkbox_field_name)
        if bool(checkbox_field.data) == self.required:
            super(IfChecked, self).__call__(form, field)


class NotRequiredIfChecked(IfChecked):
    def __init__(self, checkbox_field_name, *args, **kwargs):
        super(NotRequiredIfChecked, self).__init__(checkbox_field_name, required=False, *args, **kwargs)


class RequiredIfChecked(IfChecked):
    def __init__(self, checkbox_field_name, *args, **kwargs):
        super(RequiredIfChecked, self).__init__(checkbox_field_name, required=True, *args, **kwargs)


class MinMaxLengthAndEqualIfRequired(Length, InputRequired):
    def __init__(self, min, max, other_field_name, other_field_value, equalto_field_name=None, *args, **kwargs):
        self.other_field_name = other_field_name
        self.other_field_value = other_field_value
        self.equalto_field_name = equalto_field_name

        InputRequired.__init__(self, *args, **kwargs)
        Length.__init__(self, min=min, max=max)

    def __call__(self, form, field):
        other_field = form._fields.get(self.other_field_name)

        if other_field and other_field.data == self.other_field_value:
            if self.equalto_field_name:
                equalto_field = form._fields.get(self.equalto_field_name)
                if equalto_field.data != field.data:
                    raise ValidationError(f"this should match {equalto_field.label.text}")

            Length.__call__(self, form, field)
            InputRequired.__call__(self, form, field)


class RequiredIf(InputRequired):
    def __init__(self, other_field_name, other_field_value, *args, **kwargs):
        self.other_field_name = other_field_name
        self.other_field_value = other_field_value
        super(RequiredIf, self).__init__(*args, **kwargs)

    def __call__(self, form, field):
        other_field = form._fields.get(self.other_field_name)

        if other_field and other_field.data == self.other_field_value:
            super(RequiredIf, self).__call__(form, field)


class DateBetween(object):
    def __init__(self, lower_bound, upper_bound):
        self.lower_bound = lower_bound
        self.upper_bound = upper_bound
        self.message = f"Date must be between {lower_bound:%Y-%m-%d} and {upper_bound:%Y-%m-%d}"

    def __call__(self, form, field):
        if not field.data or field.data > self.upper_bound or field.data < self.lower_bound:
            raise ValidationError(self.message)


class RequiredDateBetweenIfChecked(DateBetween, RequiredIfChecked):
    def __init__(self, checkbox_field_name, lower_bound, upper_bound, *args, **kwargs):
        RequiredIfChecked.__init__(self, checkbox_field_name)
        DateBetween.__init__(self, lower_bound, upper_bound)

    def __call__(self, form, field):
        RequiredIfChecked.__call__(self, form, field)

        checkbox_field = form._fields.get(self.checkbox_field_name)
        if bool(checkbox_field.data):
            DateBetween.__call__(self, form, field)

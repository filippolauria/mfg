# -*- coding: utf-8 -*-
#
#  forms.py
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

from flask_wtf import FlaskForm
from wtforms import IntegerField, BooleanField, PasswordField, StringField, HiddenField, SelectMultipleField, \
                    DateField, SelectField
from wtforms.validators import Length, Regexp, EqualTo, Email, InputRequired
from wtforms.widgets import EmailInput
from wtforms_sqlalchemy.orm import model_form

from mfg import db
from mfg.models import Organization, Domain

from mfg.helpers.validators import UserAlreadyExists, EmailAlreadyUsed
from mfg.helpers.widgets import DateInput


class SingleEmailForm(FlaskForm):
    email = StringField('Email', [Length(min=4, max=64), Email(), InputRequired()],
                        render_kw={'class': 'input', 'placeholder': 'Email'}, widget=EmailInput())


class MultipleSelectForm(FlaskForm):
    field = SelectMultipleField('Select multiple values', coerce=int, choices=[])


class UidForm(FlaskForm):
    uid = HiddenField()


class LoginForm(FlaskForm):
    username = StringField('Username', [Length(min=4, max=64)], render_kw={'class': 'input is-large',
                                                                           'placeholder': 'Username'})
    password = PasswordField('Password', [Length(min=4, max=64)], render_kw={'class': 'input is-large',
                                                                             'placeholder': 'Password'})
    remember = BooleanField('Remember me')


field_args = {
    'shortname': {
        'validators': [Length(min=2, max=64)], 'render_kw': {'class': 'input',
                                                             'placeholder': 'Organization Short Name'}
    },
    'fullname': {
        'validators': [Length(min=4, max=253)], 'render_kw': {'class': 'input',
                                                              'placeholder': 'Organization Name'}
    }
}
OrganizationForm = model_form(Organization, base_class=FlaskForm, db_session=db.session,
                              field_args=field_args, exclude=['users'])


domain_name_pattern = '^([a-zA-Z0-9._-])+$'
domain_name_message = 'only upper and lower case letters, numbers and . _ - are allowed'
field_args = {
    'domain_name': {
        'validators': [Length(min=4, max=253), Regexp(domain_name_pattern, message=domain_name_message)],
        'render_kw': {'class': 'input', 'placeholder': 'Domain name', 'pattern': domain_name_pattern,
                      'title': domain_name_message}
    },
}
DomainForm = model_form(Domain, base_class=FlaskForm, db_session=db.session, field_args=field_args, exclude=['id'])


class PasswordForm(FlaskForm):
    password1 = PasswordField('Password', [Length(min=4, max=64),
                                           EqualTo('password2', message='Passwords must match')],
                              render_kw={'class': 'input', 'placeholder': 'Password'})
    password2 = PasswordField('Repeat Password', [Length(min=4, max=64)],
                              render_kw={'class': 'input', 'placeholder': 'Repeat Password'})


class UserPersonInfoForm(FlaskForm):
    firstname = StringField('First Name', [Length(min=4, max=64), InputRequired()],
                            render_kw={'class': 'input', 'placeholder': 'First Name'})
    lastname = StringField('Last Name', [Length(min=4, max=64), InputRequired()],
                           render_kw={'class': 'input', 'placeholder': 'Last Name'})


class AutoSignupForm(UserPersonInfoForm, PasswordForm):
    pass


class AutoSignupWithOrganizationSelectionFrom(AutoSignupForm):
    organization = SelectField('Organization', [InputRequired()])


class FirstAccessForm(UserPersonInfoForm, PasswordForm, OrganizationForm):
    email = StringField('Email', [Length(min=4, max=64), Email(), InputRequired(), EmailAlreadyUsed()],
                        render_kw={'class': 'input', 'placeholder': 'Email'}, widget=EmailInput())
    username = StringField('Username', [Length(min=4, max=64), InputRequired(), UserAlreadyExists()],
                           render_kw={'class': 'input', 'placeholder': 'Username'})


class UserForm(UserPersonInfoForm, PasswordForm):
    email = StringField('Email', [Length(min=4, max=64), Email(), InputRequired(), EmailAlreadyUsed()],
                        render_kw={'class': 'input', 'placeholder': 'Email'}, widget=EmailInput())

    organization = SelectField('Organization', [InputRequired()])

    username = StringField('Username', [Length(min=4, max=64), InputRequired(), UserAlreadyExists()],
                           render_kw={'class': 'input', 'placeholder': 'Username'})

    registration_method = SelectField('Registration Method', [InputRequired()],
                                      choices=[('password_by_admin', 'Specify a password for the new user'),
                                               ('link_via_mail', 'Send an activation link via mail')])

    self_renew = BooleanField('Once expired, can password be self-renewed?')
    expires_in = IntegerField('Password for this account expires every X days', [InputRequired()],
                              render_kw={'class': 'input', 'placeholder': 'X'})

    auto_disable = BooleanField('Should this account automatically disable?')
    disable_on = DateField('The account disables on', widget=DateInput(), render_kw={'class': 'input'})


class RecoverWithEmailForm(FlaskForm):
    field = StringField('Email', [Length(min=4, max=64), Email(), InputRequired()],
                        render_kw={'class': 'input', 'placeholder': 'Email'}, widget=EmailInput(),
                        description='Please specify a valid email address')


class RecoverWithUsernameForm(FlaskForm):
    field = StringField('Username', [Length(min=4, max=64), InputRequired()],
                        render_kw={'class': 'input', 'placeholder': 'Username'},
                        description='Please specify a valid username')


class SearchFiltersForm(FlaskForm):
    organizations = SelectMultipleField('Select multiple organizations', coerce=int, choices=[])
    expired = BooleanField('Show expired', default=False)
    disabled = BooleanField('Show disabled', default=False)
    expiring_soon = BooleanField('Show expiring soon', default=False)
    contact_persons = BooleanField('Show contact persons', default=False)


class SearchByUsernameForm(FlaskForm):
    username = StringField('Username', [Length(min=4, max=64), InputRequired()],
                           render_kw={'class': 'input is-large', 'placeholder': 'Username',
                                      'list': 'search-by-username-datalist'})


class GroupForm(FlaskForm):
    groupname = StringField('Group name', [Length(min=4, max=64), InputRequired()],
                            render_kw={'class': 'input', 'placeholder': 'group name'})
    group_id = HiddenField()


class RadTableForm(FlaskForm):
    attribute = StringField('Attribute', [Length(min=4, max=64), InputRequired()],
                            render_kw={'class': 'input', 'placeholder': 'attribute', 'list': 'attributes-list'})
    op = StringField('Op', [Length(min=1, max=2), InputRequired()],
                     render_kw={'class': 'input', 'placeholder': 'op', 'list': 'operators-list'})
    value = StringField('Value', [Length(min=0, max=253)],
                        render_kw={'class': 'input', 'placeholder': 'value'})
    attribute_id = HiddenField()

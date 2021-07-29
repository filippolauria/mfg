# -*- coding: utf-8 -*-
#
#  blueprints/auth.py
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

from datetime import datetime, date, timedelta
from flask import Blueprint, render_template, redirect, url_for, request, abort, flash
from flask_login import login_user, logout_user, login_required
from sqlalchemy.exc import SQLAlchemyError

from mfg import db
from mfg.models import User, Domain, Organization, Radcheck, SignupToken, WaitingForApproval
from mfg.forms import LoginForm, SingleEmailForm, AutoSignupForm, AutoSignupWithOrganizationSelectionFrom
from mfg.helpers.hashes import check_password_hash, allowed_hashing_methods, make_hash
from mfg.helpers.config import ConfigManager, OrganizationConfigManager
from mfg.helpers.utils import flash_errors, make_token, lowercase_filter_word

auth = Blueprint('auth', __name__)


@auth.route('/signup/<regex("[a-f0-9]{32}"):token>', methods=['GET', 'POST'])
def signup_finalization(token):
    """
    this view allows to finalize the self-signup procedure.
    """
    try:
        # we try to retrieve the associated SignupToken object
        this_token = db.session.query(SignupToken).filter_by(token=token).first()

        # if the token is invalid, we return a HTTP 404 error
        if not this_token:
            # TODO log
            abort(404)

        # if the token has expired, we return a HTTP 410 error
        if datetime.now() > this_token.expires_on:
            # TODO log
            abort(410)

        # first we check if auto signup feature is still globally enabled (0 disabled, 1 enabled)
        auto_signup_method = ConfigManager.get('auto.signup.method')
        if auto_signup_method == 0:
            # if the auto signup feature is disabled, we delete the token
            db.session.delete(this_token)
            db.session.commit()
            # TODO log
            return render_template('signup_finalization.html', conf=ConfigManager)

        # if the auto signup feature is globally enabled,
        # we try to deduce the organization(s) starting from the email associated with the SignupToken
        domain_name = this_token.email.split('@')[1].lower()
        domain_obj = db.session.query(Domain).filter(Domain.domain_name == domain_name).first()
        if len(domain_obj.organizations) == 1:
            # if we have only one organization we instantiate the simple AutoSignupForm...
            form = AutoSignupForm(request.form)
            one_organization = True
        else:
            # ... otherwise we instantiate the more complex AutoSignupWithOrganizationSelectionFrom
            form = AutoSignupWithOrganizationSelectionFrom(request.form)
            choices = [(int(o.id), o.shortname) for o in domain_obj.organizations]
            form.organizations.choices = choices
            one_organization = False

        if request.method == 'POST':
            if not form.validate():
                flash_errors(form)
                return render_template('signup_finalization.html', conf=ConfigManager, form=form)

            # we have a valid submitted form
            if one_organization:
                # the domain names retrieved from the email is associated with only one organization,
                # we retrieve the organization
                organization = domain_obj.organizations[0]
            else:
                # the domain names retrieved from the email is associated with more than one organizations,
                # we rely on the organization chosen by the user, which is guaranteed, by form validation,
                # to be among the proposed alternatives
                organization = db.session.query(Organization).filter(Organization.id == form.organization.data).first()

            # once we have a valid organization, we can use it to check
            # if the auto signup feature is enabled for that organization
            # 0 disabled, 1 approval always required, 2 approval only when needed
            organization_auto_signup_method = OrganizationConfigManager(organization).get('auto.signup.method')

            # if auto signup feature is disabled for this organization, we don't procede further
            if organization_auto_signup_method == 0:
                # TODO log
                return render_template('signup_finalization.html', conf=ConfigManager)

            # we start creating firstname, lastname and hash
            firstname = form.firstname.data.title()
            lastname = form.lastname.data.title()
            hash_type = ConfigManager.get('hasing.algorithm')
            hash_value = make_hash(form.password1.data, hash_type)

            # then we create the username starting from firstname and lastname
            username = lowercase_filter_word(firstname.lower()) + "." + lowercase_filter_word(lastname.lower())
            # once we have a candidate username, we try to get the user_obj
            user_obj = db.session.query(User).filter(User.username == username).first()

            # approval is needed if:
            # organization has been selected by the user
            # or the username already exists
            # or if the approval is always required for this organization
            should_be_approved = not one_organization or bool(user_obj) or organization_auto_signup_method == 1

            if should_be_approved:
                # if the new user should be approved,
                # we start creating a new request for approval
                new_user = WaitingForApproval(email=this_token.email, firstname=firstname, lastname=lastname,
                                              created_on=date.today(), hash_type=hash_type, hash_value=hash_value)

                # if the username does not already exist, we associate it to the request
                if not bool(user_obj):
                    new_user.username = username

                # then we associate the organization, too
                new_user.organization = organization
                db.session.add(new_user)

                # TODO send email
                # TODO log
                flash("Your account is waiting for approval. Check your email for further details.", 'success')
            else:
                today = date.today()
                # if the approval is not needed, we create the new user.

                # max_disable_after is the number of days after which the account has to be disabled...
                max_disable_after = OrganizationConfigManager.get('account.disabled.after.months') * 30
                # ... and disable_on is the date when this has to happen
                disable_on = today + timedelta(days=max_disable_after)

                # the new_user object is created
                new_user = User(email=this_token.email, firstname=firstname, lastname=lastname, username=username,
                                disable_on=disable_on, created_on=today)
                # and the organization is associated to it
                new_user.organization = organization
                db.session.add(new_user)

                # also, a %-Password attribute is added to the RADIUS radcheck table
                radcheck_record = Radcheck(username=username, attribute=hash_type, op=':=', value=hash_value)
                db.session.add(radcheck_record)

                # TODO send email
                # TODO log
                flash("Your account has been created. Check your email for further details.", 'success')

            db.session.delete(this_token)
            db.session.commit()

    except SQLAlchemyError as e:
        # TODO replace the exception text with a custom error message
        # TODO log the exception (to db ?, to file ?)
        flash(str(e), 'danger')

    return render_template('signup_finalization.html', conf=ConfigManager, form=form)


@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    this view allows to start the self-signup procedure.
    """
    try:
        # first we check if auto signup feature is globally enabled (0 disabled, 1 enabled)
        is_auto_signup_enabled = bool(ConfigManager.get('auto.signup.method'))
        if not is_auto_signup_enabled:
            return render_template('signup.html', conf=ConfigManager)

        # then we present a form where the user can insert their email
        form = SingleEmailForm(request.form)
        if request.method == 'POST':
            if not form.validate():
                flash_errors(form)
                return render_template('signup.html', conf=ConfigManager, form=form)

            # if the submitted data is valid, we can procede
            email = form.email.data

            # we get an eventual user obj and the domain name associated with the submitted email
            user_obj = db.session.query(User).filter(User.email == email).first()
            domain_name = email.split('@')[1].lower()
            domain_obj = db.session.query(Domain).filter(Domain.domain_name == domain_name).first()

            # we cannot procede if
            # an user associated with the submitted email already exists or
            # the retrieve domain is unknown or not associated with any organization
            if user_obj or not (domain_obj and domain_obj.organizations):
                flash("This email cannot be used for signing up", 'danger')
                return render_template('signup.html', conf=ConfigManager, form=form)

            # a domain name can be associated with more than one organization
            # if we can find at least one organization which has auto signup enabled, we can procede
            found = False
            for o in domain_obj.organizations:
                if bool(OrganizationConfigManager(o).get('auto.signup.method')):
                    found = True
                    break

            # if no organization can be found, we cannot procede...
            if not found:
                flash("Your organization does not allow the auto signup procedure", 'danger')
                return render_template('signup.html', conf=ConfigManager, form=form)

            # ... otherwise, we delete all SignupToken associated with this email...
            db.session.query(SignupToken).filter(SignupToken.email == email).delete()

            # ... and create a new SignupToken
            hours = ConfigManager.get('max.token.expired.after.hours')
            token_expires_on = datetime.now() + timedelta(hours=hours)
            new_token = SignupToken(token=make_token(), expires_on=token_expires_on, email=email)
            db.session.add(new_token)

            db.session.commit()

            # we send the token via mail
            # TODO send email
            # TODO log

            # and finally we inform the user
            flash("An email has been sent to the address you indicated", 'success')

            # we flush and disable the email field
            form.email.data = ''
            form.email.render_kw['disabled'] = ''

    except SQLAlchemyError as e:
        # TODO replace the exception text with a custom error message
        # TODO log the exception (to db ?, to file ?)
        flash(str(e), 'danger')

    return render_template('signup.html', conf=ConfigManager, form=form)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    """
    this view allows user to login.
    """

    # we instantiate the login form
    form = LoginForm(request.form)

    # if form has been submitted and it is valid
    if request.method == 'POST':
        if not form.validate():
            flash_errors(form)
            return redirect(url_for('auth.login'))

        username = form.username.data
        user = db.session.query(User).filter_by(username=username).first()

        # we can procede only if the user exists and is active
        found = False
        if user and user.is_active:
            # even though we have a default authentication method,
            # we check against all '%-Password' attributes associated with this user in the radcheck table
            password_attributes = db.session.query(Radcheck).filter((Radcheck.username == username) &
                                                                    (Radcheck.attribute.like('%-Password'))).all()

            for radcheck_attribute in password_attributes:
                try:
                    type_ = radcheck_attribute.attribute
                    if type_ in allowed_hashing_methods:
                        found = check_password_hash(form.password.data, radcheck_attribute.value, type_)
                        break
                except ValueError:
                    continue
        else:
            found = False

        if not found:
            flash('Please check your login details and try again.')
            return redirect(url_for('auth.login'))

        # if the above check passes, then we know the user has the right credentials
        login_user(user, remember=form.remember.data)
        return redirect(url_for('main.dashboard'))

    # get method
    return render_template('login.html', conf=ConfigManager, form=form)


@auth.route('/logout')
@login_required
def logout():
    """
    this view allows user to logout.
    """
    logout_user()
    return redirect(url_for('main.index'))

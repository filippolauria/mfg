# -*- coding: utf-8 -*-
#
#  blueprints/user.py
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
from flask import Blueprint, render_template, redirect, url_for, request, flash, abort
from flask_login import current_user
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy_utils.functions import escape_like
from wtforms.widgets.html5 import NumberInput
from wtforms.validators import NumberRange

from mfg import db
from mfg.config import account_disabled_groupname, password_expired_groupname
from mfg.forms import UidForm, UserForm, PasswordForm, RecoverWithEmailForm, RecoverWithUsernameForm, \
                          SearchFiltersForm, SearchByUsernameForm
from mfg.models import Organization, ActionEnum, Token, User, Group, Radcheck, Radreply, Radacct, Radpostauth

from mfg.helpers.config import ConfigManager, OrganizationConfigManager
from mfg.helpers.decorators import is_admin, is_admin_or_contact_person, is_authenticated
from mfg.helpers.hashes import make_hash, check_password_hash
from mfg.helpers.utils import flash_errors, make_token
from mfg.helpers.validators import RequiredDateBetweenIfChecked, MinMaxLengthAndEqualIfRequired
from mfg.helpers.widgets import DateInput


user = Blueprint('user', __name__)


@user.route('/user/search', methods=['GET', 'POST'])
@is_admin_or_contact_person
def search():
    """
    this view allows an admin or a contact person to search user by username
    """

    # we get a list of organization IDs which can be managed
    # by the current admin (all the organizations) or
    # by the current contact person
    org_ids = [x.id for x in current_user.managed_organizations()]

    # we instantiate the form used for searching user by username
    form = SearchByUsernameForm(request.form)

    # we populate the user datalist (HTML 5)
    user_datalist = db.session.query(User).with_entities(User.username).filter(
                                     User.organization_id.in_(org_ids)).order_by(User.lastname).all()

    users = None
    if request.method == 'POST':
        if not form.validate():
            # if the method is post and form does not validate we flash errors to the current admin or contact person
            flash_errors(form)
        else:
            # we escape the data provided by the current admin or contact person to avoid SQL-Injection
            param = "%" + escape_like(form.username.data) + "%"
            users = db.session.query(User).filter((User.username.like(param)) &
                                                  (User.organization_id.in_(org_ids))).order_by(User.lastname).all()

    return render_template('user/search.html', conf=ConfigManager, current_user=current_user, form=form, users=users,
                           user_datalist=user_datalist)


@user.route('/user/list/<int:pagenum>', methods=['GET', 'POST'])
@user.route('/user/list', methods=['GET', 'POST'])
@is_admin_or_contact_person
def list(pagenum=1):
    """
    This view allows the current admin or contact person to list users.
    The view is paginated (on pagenum param) and also allow to specify some search filter.
    """

    # we instantiate a simple UidForm which is used to delete an user by ID
    uid_form = UidForm()

    # we get a list of organization which can be managed
    # by the current admin (all the organizations) or
    # by the current contact person
    organizations = current_user.managed_organizations()
    org_ids = [o.id for o in organizations]

    # we also prepare a list of choices (id, shortname) for populating the search_form organizations filter
    choices = [(int(o.id), o.shortname) for o in organizations]
    search_form = SearchFiltersForm(request.form)
    search_form.organizations.choices = choices

    # we get the number of days before the account expiration.
    # During this time the account is considered as "expiring"
    expires_in_days = ConfigManager.get('alert.when.password.expires.in.days')
    # we update the filter label
    search_form.expiring_soon.label.text = f"Show expiring in {expires_in_days} days"

    # we initialize some useful variables
    usernames = []
    expiring_soon = False
    expired = False
    disabled = False
    contact_persons = False

    if request.method == 'POST':
        if not search_form.validate():
            # if the method is post and form does not validate we flash errors to the current admin or contact person
            flash_errors(search_form)
        else:
            # we initialize the variables with data posted by the current admin or contact person
            expired = bool(search_form.expired.data)
            disabled = bool(search_form.disabled.data)
            expiring_soon = bool(search_form.expiring_soon.data)
            contact_persons = bool(search_form.contact_persons.data)

            # if we have to filter for expired or disabled users...
            if any([expired, disabled]):
                filters = []

                if expired:
                    filters.append(Group.groupname == password_expired_groupname)

                if disabled:
                    filters.append(Group.groupname == account_disabled_groupname)

                # ... we build up an appropriate filter
                # that we pass to a db query...
                query = User.query.with_entities(User.username).join(User.groups).filter(db.or_(*filters)).distinct()
                # ... collecting the results in the result variable
                result = query.all()

                # we then update the list of unique usernames
                for r in result:
                    if r.username not in usernames:
                        usernames.append(r.username)

            # if we have to filter for expiring or contact persons...
            if any([expiring_soon, contact_persons]):
                filters = []

                if expiring_soon:
                    expires_on = date.today() + timedelta(days=expires_in_days)
                    filters.append(User.expires_on <= expires_on)

                if contact_persons:
                    filters.append(User.organizations.any(Organization.id.in_(org_ids)))

                # ... we build up an appropriate filter
                # that we pass to a db query...
                query = User.query.with_entities(User.username).filter(db.or_(*filters)).distinct()
                # ... collecting the results in the result variable
                result = query.all()

                # we then update the list of unique usernames
                for r in result:
                    if r.username not in usernames:
                        usernames.append(r.username)
    else:
        # if the method is GET we select all the organizations
        search_form.organizations.data = org_ids

    # we start building another query:
    # we start creating a filter for the selected organizations
    filters = [User.organization_id.in_(search_form.organizations.data)]

    # if we have to filter for expired, disabled, expiring or contact persons
    # we use the previously created list of usernames as a filter too
    if any([expired, disabled, expiring_soon, contact_persons]):
        filters.append(User.username.in_(usernames))

    # we get the allowed number of items per page
    items_per_page = ConfigManager.get('max.items.per.page')

    # finally we execute the query with the appropriate filters and paginate the result
    users = db.session.query(User).filter(db.and_(*filters)).order_by(User.lastname).paginate(page=pagenum,
                                                                                              per_page=items_per_page)
    return render_template('user/list.html', conf=ConfigManager, current_user=current_user, users=users,
                           uid_form=uid_form, search_form=search_form)


@user.route('/user/toggle_admin', methods=['POST'])
@is_admin
def toggle_admin():
    """
    csrf_token protected path to toggle admin status for an user
    """

    # we instantiate a simple UidForm
    form = UidForm(request.form)
    if not form.validate():
        # if the form is not valid, we flash an error message to the current admin...
        flash("Select an user from the following list", "danger")
        # ... then we redirect to user list
        return redirect(url_for('user.list'))

    try:
        # we get the uid and cast it to integer
        uid = int(form.uid.data)
        this_user = db.session.query(User).get(uid)

        # we ensure that the associated user is valid...
        if not this_user:
            flash("Select an user from the following list", 'danger')
            return redirect(url_for('user.list'))

        # ... and that the current admin is not trying to self-update its admin status
        if uid == current_user.id:
            flash("Only another admin can update your admin status", 'danger')
            return redirect(url_for('user.details', uid=uid))

        # we toggle the admin status
        this_user.is_admin = not bool(this_user.is_admin)

        # if we toggle the admin status, we eventually clear existing managed organizations
        if this_user.is_admin:
            this_user.organizations = []

        # we commit changes to db
        db.session.commit()

        # we build the exit message
        message = this_user.fullname()
        message += " is now an administrator" if this_user.is_admin else " is not an administrator anymore"

        flash(message, "success")
        return redirect(url_for('user.details', uid=uid))

    except ValueError:
        flash("The user you selected is not valid", 'danger')
    except SQLAlchemyError as e:
        # TODO rollback (?)
        # TODO replace the exception text with a custom error message
        # TODO log the exception (to db ?, to file ?)
        flash(str(e), 'danger')

    return redirect(url_for('user.list'))


@user.route('/user/delete', methods=['POST'])
@is_admin_or_contact_person
def delete():
    """
    csrf_token protected path to delete an user
    """

    # we instantiate a simple UidForm
    form = UidForm(request.form)
    if not form.validate():
        # if the form is not valid, we flash an error message to the current admin...
        flash("Select an user from the following list", "danger")
        # ... then we redirect to user list
        return redirect(url_for('user.list'))

    # we get a list of organization IDs which can be managed
    # by the current admin (all the organizations) or
    # by the current contact person
    org_ids = [x.id for x in current_user.managed_organizations()]

    try:
        # we get the uid and cast it to integer
        uid = int(form.uid.data)
        this_user = db.session.query(User).get(uid)

        # we ensure that the associated user is valid and that they belong to an allowed organization
        if not this_user or this_user.organization_id not in org_ids:
            flash("Select an user from the following list", "danger")
            return redirect(url_for('user.list'))

        # we also ensure that current admin or contact person is not trying to delete themself
        if current_user.id == uid:
            flash("You cannot delete yourself", "danger")
            return redirect(url_for('user.list'))

        db.session.delete(this_user)
        db.session.commit()
        flash("User has been successfully deleted", "success")
    except ValueError:
        # TODO log security warning
        flash("The user you selected is not valid", 'danger')
    except SQLAlchemyError as e:
        # TODO replace the exception text with a custom error message
        # TODO log the exception (to db ?, to file ?)
        flash(str(e), 'danger')

    return redirect(url_for('user.list'))


def forgot_password_helper(FormClass, field_name):
    """
    helper function for views that allow to recover password by username and by email
    """

    # we instantiate the right form
    form = FormClass(request.form)

    if request.method == 'POST':
        if not form.validate():
            flash_errors(form)
            return render_template('user/forgot_password.html', conf=ConfigManager, current_user=current_user,
                                   form=form, field=field_name)

        try:
            # we select the right query to use (and the return message), according to the field_name value
            if field_name == 'email':
                user_obj = db.session.query(User).filter_by(email=form.field.data).first()
                message = "An email containing recover instructions has been sent to the specified email address."
            else:
                field_name = 'username'
                user_obj = db.session.query(User).filter_by(username=form.field.data).first()
                message = "An email containing recover instructions has been sent to the email address associated " \
                          "with the specified username."

            # if an user_obj has been retrieved
            if user_obj:
                # we delete all old tokens related to the selected user...
                db.session.query(Token).filter(Token.user_id == user_obj.id).delete()

                # ... and add a new token for them
                hours = OrganizationConfigManager(user_obj.organization).get('token.expired.after.hours')
                token_expires_on = datetime.now() + timedelta(hours=hours)
                new_token = Token(token=make_token(), expires_on=token_expires_on, action=ActionEnum.reset,
                                  user_id=user_obj.id)
                db.session.add(new_token)

                db.session.commit()

                # TODO send the email with the password reset URL

            # we clear the field value, then flash the status message (even if we have not found a valid user)
            form.field.data = ""
            flash(message, "success")
        except SQLAlchemyError as e:
            # TODO replace the exception text with a custom error message
            # TODO log the exception (to db ?, to file ?)
            flash(str(e), 'danger')

    return render_template('user/forgot_password.html', conf=ConfigManager, current_user=current_user, form=form,
                           field=field_name)


@user.route('/user/forgot_password::username', methods=['GET', 'POST'])
def forgot_password_username():
    """
    this view uses the above helper for the password reset feature by providing a valid username.
    """
    return forgot_password_helper(RecoverWithUsernameForm, 'username')


@user.route('/user/forgot_password::email', methods=['GET', 'POST'])
def forgot_password_email():
    """
    this view uses the above helper for the password reset feature by providing a valid email address.
    """
    return forgot_password_helper(RecoverWithEmailForm, 'email')


@user.route('/user/<regex("[a-f0-9]{32}"):token>', methods=['GET', 'POST'])
def reset_or_activate(token):
    """
    this view allows to reset or activate an account, by providing a valid token
    """

    try:
        # we try to retrieve the associated token object
        this_token = db.session.query(Token).filter_by(token=token).first()

        # if the token is invalid, we return a HTTP 404 error
        if not this_token:
            # TODO log
            abort(404)

        # if the token has expired, we return a HTTP 410 error
        if datetime.now() > this_token.expires_on:
            # TODO log
            abort(410)

        # we instantiate the reset password form
        form = PasswordForm(request.form)
        if request.method == 'POST':
            if not form.validate():
                # if the method is post and form does not validate,
                # we flash errors to the current admin or contact person
                flash_errors(form)
            else:
                # we get the associated user and eventually activate it
                user_obj = this_token.user
                user_obj.is_active = True
                default_password_set = False

                if this_token.action == ActionEnum.reset:
                    # retrieve all password attributes
                    attrs = Radcheck.query.filter(Radcheck.attribute.like("%-Password")).all()

                    password_valid = True

                    # we don't allow to reuse the last used password, so we check all the %-Password attribute
                    for attr in attrs:
                        try:
                            password_match = check_password_hash(form.password1.data, attr.value, attr.attribute)
                            if password_match:
                                password_valid = False
                                break

                        except ValueError:
                            # TODO log => attr.attribute algorithm not implemented
                            continue

                    if not password_valid:
                        flash("The password that you have chosen is similar to the last used password", 'danger')
                    else:
                        # if the password is valid we update all other password attributes
                        for attr in attrs:
                            try:
                                hash_ = make_hash(form.password1.data, attr.attribute)
                                attr.value = hash_

                            except ValueError:
                                # TODO log => attr.attribute algorithm not implemented
                                continue

                    # we also check that the default password attribute has been set
                    hash_type = ConfigManager.get('hasing.algorithm')
                    default_password_set = Radcheck.query.filter(Radcheck.attribute == hash_type).first()

                    message = f"Password for {user_obj.username} has been successfully reset"

                # if we don't have set the default password type or the action is activate
                if not default_password_set or this_token.action == ActionEnum.activate:
                    # we create a new hash
                    hash_type = ConfigManager.get('hasing.algorithm')
                    hash_ = make_hash(form.password1.data, hash_type)

                    # and add a new attr
                    attr = Radcheck(username=user_obj.username, attribute=hash_type, op=':=', value=hash_)
                    db.session.add(attr)

                    if not default_password_set:
                        message = f"Password for {user_obj.username} has been successfully reset"
                    else:
                        message = f"Account for {user_obj.username} has been successfully activated"

                # clean tokens
                db.session.delete(this_token)
                db.session.commit()
                flash(message, 'success')

                # make form not available
                form = None

    except SQLAlchemyError as e:
        # TODO replace the exception text with a custom error message
        # TODO log the exception (to db ?, to file ?)
        flash(str(e), 'danger')

    return render_template('user/reset_or_activate.html', conf=ConfigManager, current_user=current_user, form=form,
                           token=this_token)


@user.route('/user/create', methods=['GET', 'POST'])
@is_admin_or_contact_person
def create():
    """
    this view is used for creating other users
    """

    # we prepare the list of the organizations
    organizations = current_user.managed_organizations()
    # ~ org_ids = [o.id for o in organizations]
    choices = [(str(o.id), o.shortname) for o in organizations]

    # then we start instantiating the form
    form = UserForm(request.form)
    form.organization.choices = choices

    # passwords are required if the registration method is 'password_by_admin'
    form.password1.validators = [MinMaxLengthAndEqualIfRequired(4, 64, 'registration_method',
                                                                'password_by_admin', equalto_field_name='password2')]
    form.password2.validators = [MinMaxLengthAndEqualIfRequired(4, 64, 'registration_method', 'password_by_admin')]

    # we set the maximum date for disable
    today = date.today()
    tomorrow = today + timedelta(days=1)
    max_disable_after = ConfigManager.get('max.account.disabled.after.months') * 30
    disable_on_date = today + timedelta(days=max_disable_after)
    form.disable_on.widget = DateInput(step=1, min=f"{tomorrow:%Y-%m-%d}", max=f"{disable_on_date:%Y-%m-%d}")
    form.disable_on.validators = [RequiredDateBetweenIfChecked('auto_disable', tomorrow, disable_on_date)]

    # we set the expiration date
    max_expires_after = ConfigManager.get('max.password.expired.after.days')
    form.expires_in.widget = NumberInput(step=1, min=1, max=max_expires_after)
    form.expires_in.validators.append(NumberRange(min=1, max=max_expires_after))
    form.expires_in.data = max_expires_after

    if request.method == 'POST':
        if not form.validate():
            flash_errors(form)
            return render_template('user/create.html', conf=ConfigManager, current_user=current_user, form=form)

        self_renew = bool(form.self_renew.data)
        auto_disable = bool(form.auto_disable.data)
        organization_id = int(form.organization.data)
        is_active = bool(form.registration_method.data == 'password_by_admin')
        disable_on = form.disable_on.data

        # check if the password expires before the account is automatically disabled
        expires_on = today + timedelta(days=int(form.expires_in.data))
        if auto_disable and disable_on and (expires_on > disable_on or expires_on < tomorrow):
            flash('You have chosen an invalid number of days for the password expiration.', 'danger')
            return render_template('user/create.html', conf=ConfigManager, current_user=current_user, form=form)

        try:
            username = form.username.data
            new_user = User(email=form.email.data, firstname=form.firstname.data.title(),
                            lastname=form.lastname.data.title(), username=username, self_renew=self_renew,
                            is_admin=False, expires_on=expires_on, creator_id=current_user.get_id(),
                            created_on=today, organization_id=organization_id, is_active=is_active)

            if auto_disable:
                new_user.disable_on = disable_on

            db.session.add(new_user)

            # this is a new user, we check if radius contains stale attributes
            db.session.query(Radcheck).filter(Radcheck.username == username).delete()
            db.session.query(Radreply).filter(Radreply.username == username).delete()
            db.session.query(Radpostauth).filter(Radpostauth.username == username).delete()
            db.session.query(Radacct).filter(Radacct.username == username).delete()

            # chose according to registration method
            if form.registration_method.data == 'password_by_admin':
                hash_type = ConfigManager.get('hasing.algorithm')
                hash_ = make_hash(form.password1.data, hash_type)
                radcheck_record = Radcheck(username=username, attribute=hash_type, op=':=', value=hash_)
                db.session.add(radcheck_record)
            else:
                max_token_expires_after = ConfigManager.get('max.token.expired.after.hours')
                token_expires_on = datetime.now() + timedelta(hours=max_token_expires_after)
                new_token = Token(token=make_token(), expires_on=token_expires_on,
                                  action=ActionEnum.activate, user_id=new_user.id)
                db.session.add(new_token)

            db.session.commit()
            for field in form:
                field.data = ""
            flash(f"User {username} has been added", 'success')

        except SQLAlchemyError as e:
            flash(str(e), 'danger')

    return render_template('user/create.html', conf=ConfigManager, current_user=current_user, form=form)


@user.route('/user/details/<int:uid>', methods=['GET'])
@is_authenticated
def details(uid):
    """
    this view is used by an authenticated user to show user details
    """

    # retrieve the user object associated to the provided uid
    this_user = db.session.query(User).get(uid)

    if current_user.is_admin_or_contact_person():
        # we get a list of organization IDs which can be managed
        # by the current admin (all the organizations) or
        # by the current contact person
        org_ids = [x.id for x in current_user.managed_organizations()]

        if not this_user:
            # TODO log
            abort(404)

        if this_user.organization_id not in org_ids:
            # TODO log
            abort(403)

        # we instantiate an UidForm
        form = UidForm()

    else:
        # a simple user can access only to their details
        if not this_user or uid != current_user.id:
            # TODO log
            abort(403)

        form = None

    return render_template('user/details.html', conf=ConfigManager, current_user=current_user, user=this_user,
                           form=form)

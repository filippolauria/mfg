# -*- coding: utf-8 -*-
#
#  blueprints/organization.py
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

from flask import Blueprint, redirect, url_for, request, flash
from flask_login import current_user
from sqlalchemy.exc import SQLAlchemyError

from mfg import db
from mfg.forms import CreateOrganizationForm, UidForm, MultipleSelectForm
from mfg.models import Organization, Domain

from mfg.helpers.settings import GlobalSettingsManager, OrganizationSettingsManager
from mfg.helpers.decorators import is_admin
from mfg.helpers.utils import flash_errors, render_template


organization = Blueprint('organization', __name__)


@organization.route('/admin/organization/list')
@is_admin
def list():
    """
    this view allows admin to list all the registered organizations
    """
    organizations = db.session.query(Organization).all()

    # this form is instantiated for enabling admin to delete organization(s)
    form = UidForm()
    return render_template('organization/list.html', conf=GlobalSettingsManager, current_user=current_user,
                           organizations=organizations, form=form)


@organization.route('/admin/organization/delete', methods=['POST'])
@is_admin
def delete():
    """
    csrf_token protected path to delete an organization
    """

    # we instantiate the simple UidForm which carries an organization_id
    form = UidForm(request.form)
    if not form.validate():
        # if the form does not validate, we redirect to the organizations list
        flash("Select an organization from the following list", "danger")
        return redirect(url_for('organization.list'))

    try:
        # we get the uid and cast it to integer
        uid = int(form.uid.data)
        this_organization = db.session.query(Organization).get(uid)

        # if the organization is not valid, we redirect to the organizations list
        if not this_organization:
            flash("Select an organization from the following list", "danger")
            return redirect(url_for('organization.list'))

        # otherwise we delete the selected organization
        db.session.delete(this_organization)
        db.session.commit()
        flash("The organization has been successfully deleted", "success")

    except ValueError:
        # TODO log security warning
        flash("The organization you selected is not valid", 'danger')
    except SQLAlchemyError as e:
        # TODO replace the exception text with a custom error message
        # TODO log the exception (to db ?, to file ?)
        flash(str(e), 'danger')

    return redirect(url_for('organization.list'))


@organization.route('/admin/organization/edit/<int:uid>', methods=['GET', 'POST'])
@is_admin
def edit(uid):
    """
    this view allows admin to edit an organization
    """

    # we get the organization associated with uid
    this_organization = db.session.query(Organization).get(uid)
    # if the organization is not valid, we redirect to the organizations list
    if not this_organization:
        flash("Select an organization from the following list", 'danger')
        return redirect(url_for('organization.list'))

    # we instantiate the organization form object with the data posted by admin
    form = CreateOrganizationForm(request.form)

    if request.method == 'POST':
        if not form.validate():
            flash_errors(form)
        else:
            # if the form validates, we edit the organization
            try:
                this_organization.shortname = form.shortname.data
                this_organization.fullname = form.fullname.data

                db.session.commit()

                # then we prepare the message to be flashed back to admin
                flash(f"The organization {form.shortname.data} has been successfully edited", 'success')
            except SQLAlchemyError as e:
                # TODO replace the exception text with a custom error message
                # TODO log the exception (to db ?, to file ?)
                flash(str(e), 'danger')

    # we refresh form data and organizations list
    form.shortname.data = this_organization.shortname
    form.fullname.data = this_organization.fullname
    organizations = db.session.query(Organization).all()

    return render_template('organization/edit.html', conf=GlobalSettingsManager, current_user=current_user, form=form,
                           organizations=organizations)


@organization.route('/admin/organization/create', methods=['GET', 'POST'])
@is_admin
def create():
    """
    this view allows admin to create an organization
    """

    # we instantiate the CreateOrganizationForm object
    form = CreateOrganizationForm(request.form)
    if request.method == 'POST':
        if not form.validate():
            flash_errors(form)
        else:
            try:
                # if the form is valid, we add the new organization to the db
                new_organization = Organization(shortname=form.shortname.data, fullname=form.fullname.data)
                db.session.add(new_organization)
                db.session.commit()

                # set organization configuration defaults (triggers SQLAlchemyError exception)
                OrganizationSettingsManager(new_organization).set_default()

                # we empty the form
                form.shortname.data = ''
                form.fullname.data = ''

                # then flash the success message
                flash(f"The organization {new_organization.name()} has been successfully added", 'success')
            except SQLAlchemyError as e:
                # TODO replace the exception text with a custom error message
                # TODO log the exception (to db ?, to file ?)
                flash(str(e), 'danger')

    organizations = db.session.query(Organization).all()
    return render_template('organization/create.html', conf=GlobalSettingsManager, current_user=current_user, form=form,
                           organizations=organizations)


@organization.route('/admin/organization/associate/<int:uid>', methods=['GET', 'POST'])
@is_admin
def associate(uid):
    """
    this view allows an admin to associate domain(s) with an organization.
    """

    # we check if the selected organization exists
    this_organization = db.session.query(Organization).get(uid)
    if not this_organization:
        flash("Select an organization from the following list", 'danger')
        return redirect(url_for('organization.list'))

    # then we get a list of domain names
    domains = db.session.query(Domain).order_by(Domain.domain_name).all()

    # we preload form fields
    form = MultipleSelectForm(request.form)
    form.field.choices = [(int(domain.id), domain.domain_name) for domain in domains]
    form.field.label.text = "Select domain names"

    if request.method == 'POST':
        if not form.validate():
            flash_errors(form)
        else:
            try:
                # if the form is valid, we retrieve selected domain objects
                selected_domains = []
                for domain_id in form.field.data:
                    domain_obj = db.session.query(Domain).get(domain_id)
                    if not domain_obj:
                        continue
                    selected_domains.append(domain_obj)

                # then we update the relationship with the new (selected) domains
                this_organization.domains = selected_domains
                db.session.commit()

                # finally we prepare a message to be flashed back to the admin
                if len(selected_domains) == 0:
                    flash("All the domain name associations have been removed", 'info')
                elif len(selected_domains) == 1:
                    flash("The domain name has been associated successfully", 'success')
                else:
                    flash("The domain names have been associated successfully", 'success')

            except SQLAlchemyError as e:
                # TODO replace the exception text with a custom error message
                # TODO log the exception (to db ?, to file ?)
                flash(str(e), 'danger')

    # update selected choices
    form.field.data = [int(domain.id) for domain in this_organization.domains]

    return render_template('organization/associate.html', conf=GlobalSettingsManager, current_user=current_user, form=form,
                           organization=this_organization)

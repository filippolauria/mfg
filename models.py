# -*- coding: utf-8 -*-
#
#  models.py
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

import enum
import json
import os
from datetime import date, datetime
from flask import current_app, url_for
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.sql import expression, func
from sqlalchemy.types import Enum

from mfg import db
from mfg.helpers.hashes import check_password_hash


# we are outside the context of flask app, so we manually load
# table prefix directly from the json configuration file
# if we cannot, we fallback to 'mfg_'
table_prefix = ''
config_json = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
if (os.path.isfile(config_json) and os.access(config_json, os.R_OK)):
    with open(config_json, 'r') as fd:
        try:
            d = json.load(fd)
            table_prefix = d['MFG_DATABASE_TABLE_PREFIX']

        except Exception:
            pass

if not table_prefix:
    table_prefix = 'mfg_'


class Nas(db.Model):
    __tablename__ = 'nas'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    nasname = db.Column(db.String(128, 'utf8_bin'), nullable=False, index=True)
    shortname = db.Column(db.String(32, 'utf8_bin'))
    type = db.Column(db.String(30, 'utf8_bin'), server_default=db.FetchedValue())
    ports = db.Column(db.Integer)
    secret = db.Column(db.String(60, 'utf8_bin'), nullable=False, server_default=db.FetchedValue())
    server = db.Column(db.String(64, 'utf8_bin'))
    community = db.Column(db.String(50, 'utf8_bin'))
    description = db.Column(db.String(200, 'utf8_bin'), server_default=db.FetchedValue())


class Radacct(db.Model):
    __tablename__ = 'radacct'
    __table_args__ = {'extend_existing': True}

    radacctid = db.Column(db.BigInteger, primary_key=True)
    acctsessionid = db.Column(db.String(64, 'utf8_bin'), nullable=False, index=True, server_default=db.FetchedValue())
    acctuniqueid = db.Column(db.String(32, 'utf8_bin'), nullable=False, unique=True, server_default=db.FetchedValue())
    username = db.Column(db.String(64, 'utf8_bin'), db.ForeignKey(table_prefix + 'user.username'))
    realm = db.Column(db.String(64, 'utf8_bin'), server_default=db.FetchedValue())
    nasipaddress = db.Column(db.String(15, 'utf8_bin'), nullable=False, index=True, server_default=db.FetchedValue())
    nasportid = db.Column(db.String(15, 'utf8_bin'))
    nasporttype = db.Column(db.String(32, 'utf8_bin'))
    acctstarttime = db.Column(db.DateTime(timezone=True), index=True)
    acctupdatetime = db.Column(db.DateTime(timezone=True))
    acctstoptime = db.Column(db.DateTime(timezone=True), index=True)
    acctinterval = db.Column(db.Integer, index=True)
    acctsessiontime = db.Column(db.Integer, index=True)
    acctauthentic = db.Column(db.String(32, 'utf8_bin'))
    connectinfo_start = db.Column(db.String(50, 'utf8_bin'))
    connectinfo_stop = db.Column(db.String(50, 'utf8_bin'))
    acctinputoctets = db.Column(db.BigInteger)
    acctoutputoctets = db.Column(db.BigInteger)
    calledstationid = db.Column(db.String(50, 'utf8_bin'), nullable=False, server_default=db.FetchedValue())
    callingstationid = db.Column(db.String(50, 'utf8_bin'), nullable=False, server_default=db.FetchedValue())
    acctterminatecause = db.Column(db.String(32, 'utf8_bin'), nullable=False, server_default=db.FetchedValue())
    servicetype = db.Column(db.String(32, 'utf8_bin'))
    framedprotocol = db.Column(db.String(32, 'utf8_bin'))
    framedipaddress = db.Column(db.String(15, 'utf8_bin'), nullable=False, index=True, server_default=db.FetchedValue())

    user = db.relationship("User", back_populates="radacct_records")


t_radusergroup = db.Table('radusergroup',
                          db.Column('username', db.String(64, 'utf8_bin'),
                                    db.ForeignKey(table_prefix + 'user.username')),
                          db.Column('groupname', db.String(64, 'utf8_bin'),
                                    db.ForeignKey(table_prefix + 'group.groupname')),
                          db.Column('priority', db.Integer, nullable=False, server_default=db.FetchedValue()),
                          extend_existing=True)


class Radcheck(db.Model):
    __tablename__ = 'radcheck'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64, 'utf8_bin'), db.ForeignKey(table_prefix + 'user.username'))
    attribute = db.Column(db.String(64, 'utf8_bin'), nullable=False, server_default=db.FetchedValue())
    op = db.Column(db.String(2, 'utf8_bin'), nullable=False, server_default=db.FetchedValue())
    value = db.Column(db.String(253, 'utf8_bin'), nullable=False, server_default=db.FetchedValue())

    user = db.relationship("User", back_populates="radcheck_attributes")


class Radgroupcheck(db.Model):
    __tablename__ = 'radgroupcheck'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    groupname = db.Column(db.String(64, 'utf8_bin'),
                          db.ForeignKey(table_prefix + 'group.groupname', ondelete='CASCADE'))
    attribute = db.Column(db.String(64, 'utf8_bin'), nullable=False, server_default=db.FetchedValue())
    op = db.Column(db.String(2, 'utf8_bin'), nullable=False, server_default=db.FetchedValue())
    value = db.Column(db.String(253, 'utf8_bin'), nullable=False, server_default=db.FetchedValue())

    group = db.relationship("Group", back_populates="radgroupcheck_attributes")


class Radgroupreply(db.Model):
    __tablename__ = 'radgroupreply'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    groupname = db.Column(db.String(64, 'utf8_bin'),
                          db.ForeignKey(table_prefix + 'group.groupname', ondelete='CASCADE'))
    attribute = db.Column(db.String(64, 'utf8_bin'), nullable=False, server_default=db.FetchedValue())
    op = db.Column(db.String(2, 'utf8_bin'), nullable=False, server_default=db.FetchedValue())
    value = db.Column(db.String(253, 'utf8_bin'), nullable=False, server_default=db.FetchedValue())

    group = db.relationship("Group", back_populates="radgroupreply_attributes")


class Radpostauth(db.Model):
    __tablename__ = 'radpostauth'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64, 'utf8_bin'), db.ForeignKey(table_prefix + 'user.username'))
    _pass = db.Column('pass', db.String(64, 'utf8_bin'), nullable=False, server_default=db.FetchedValue())
    reply = db.Column(db.String(32, 'utf8_bin'), nullable=False, server_default=db.FetchedValue())
    authdate = db.Column(db.DateTime(timezone=True), nullable=False, server_default=db.FetchedValue())

    user = db.relationship("User", back_populates="radpostauth_attributes")


class Radreply(db.Model):
    __tablename__ = 'radreply'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64, 'utf8_bin'), db.ForeignKey(table_prefix + 'user.username'))
    attribute = db.Column(db.String(64, 'utf8_bin'), nullable=False, server_default=db.FetchedValue())
    op = db.Column(db.String(2, 'utf8_bin'), nullable=False, server_default=db.FetchedValue())
    value = db.Column(db.String(253, 'utf8_bin'), nullable=False, server_default=db.FetchedValue())

    user = db.relationship("User", back_populates="radreply_attributes")


t_organization_domain = db.Table(table_prefix + 'organization_domain',
                                 db.Column('organization_id', db.Integer,
                                           db.ForeignKey(table_prefix + 'organization.id'), nullable=False),
                                 db.Column('domain_id', db.Integer,
                                           db.ForeignKey(table_prefix + 'domain.id'), nullable=False),
                                 extend_existing=True)


t_contactperson_organization = db.Table(table_prefix + 'contactperson_organization',
                                        db.Column('user_id', db.Integer,
                                                  db.ForeignKey(table_prefix + 'user.id'), nullable=False),
                                        db.Column('organization_id', db.Integer,
                                                  db.ForeignKey(table_prefix + 'organization.id'), nullable=False),
                                        extend_existing=True)


t_organization_group = db.Table(table_prefix + 'organization_group',
                                db.Column('organization_id', db.Integer,
                                          db.ForeignKey(table_prefix + 'organization.id'), nullable=False),
                                db.Column('group_id', db.Integer,
                                          db.ForeignKey(table_prefix + 'group.id'), nullable=False),
                                extend_existing=True)


class Base(object):
    @declared_attr
    def createdby_id(cls):
        return db.Column(db.Integer, db.ForeignKey(table_prefix + 'user.id', ondelete='SET NULL'), nullable=True)
    
    @declared_attr
    def createdby(cls):
        return db.relationship('User', primaryjoin=lambda: User.id == cls.createdby_id)

    created_on = db.Column(db.DateTime(timezone=True), nullable=True, server_default=func.now())
    
    @declared_attr
    def modifiedby_id(cls):
        return db.Column(db.Integer, db.ForeignKey(table_prefix + 'user.id', ondelete='SET NULL'), nullable=True)

    @declared_attr
    def modifiedby(cls):
        return db.relationship('User', primaryjoin=lambda: User.id == cls.modifiedby_id)

    modified_on = db.Column(db.DateTime(timezone=True), nullable=True, onupdate=func.now())


class Organization(db.Model):
    __tablename__ = table_prefix + 'organization'

    id = db.Column(db.Integer, nullable=False, primary_key=True)
    shortname = db.Column(db.String(64, 'utf8_bin'), unique=True, nullable=False)
    fullname = db.Column(db.String(253, 'utf8_bin'), nullable=False)
    users = db.relationship('User', back_populates="organization")

    groups = db.relationship('Group', secondary=t_organization_group, back_populates='organizations')
    domains = db.relationship('Domain', secondary=t_organization_domain, back_populates='organizations')
    contact_persons = db.relationship('User', secondary=t_contactperson_organization, back_populates='organizations')
    settings = db.relationship('OrganizationSettings', back_populates="organization", passive_deletes=True)
    waiting_for_approval = db.relationship('WaitingForApproval', back_populates="organization")

    def __repr__(self):
        return f"<Organization {self.shortname}>"

    def name(self):
        return f"{self.fullname} ({self.shortname})"


class User(db.Model):
    __tablename__ = table_prefix + 'user'

    id = db.Column(db.Integer, nullable=False, primary_key=True)
    email = db.Column(db.String(253, 'utf8_bin'), nullable=False, unique=True)
    username = db.Column(db.String(64, 'utf8_bin'), nullable=False, unique=True, index=True)
    firstname = db.Column(db.String(64, 'utf8_bin'), nullable=False)
    lastname = db.Column(db.String(64, 'utf8_bin'), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False, server_default=expression.false())
    self_renew = db.Column(db.Boolean, nullable=False, default=True, server_default=expression.true())
    expires_on = db.Column(db.Date, nullable=True)
    created_on = db.Column(db.Date, nullable=False, default=date.today)
    disable_on = db.Column(db.Date, nullable=True)

    organization_id = db.Column(db.Integer, db.ForeignKey(table_prefix + 'organization.id'))
    organization = db.relationship("Organization", back_populates="users")

    creator_id = db.Column(db.Integer, db.ForeignKey(table_prefix + 'user.id'), nullable=True)
    creator = db.relationship('User', remote_side=[id])

    radcheck_attributes = db.relationship('Radcheck', back_populates='user')
    radpostauth_attributes = db.relationship('Radpostauth', back_populates='user')
    radreply_attributes = db.relationship('Radreply', back_populates='user')
    radacct_records = db.relationship('Radacct', back_populates='user')
    groups = db.relationship('Group', back_populates='users', secondary=t_radusergroup)

    tokens = db.relationship('Token', back_populates="user")
    organizations = db.relationship('Organization', back_populates='contact_persons',
                                    secondary=t_contactperson_organization)

    is_active = db.Column(db.Boolean, nullable=False, default=True, server_default=expression.true())

    def is_contact_person(self):
        return bool(self.organizations)

    def fullname(self):
        return self.lastname.upper() + " " + self.firstname

    def auto_disable(self):
        return bool(self.disable_on)

    def is_expired(self):
        groupname = current_app.config['MFG_PASSWORD_EXPIRED_GROUPNAME']
        expired_group = db.session.query(Group).filter(Group.groupname == groupname).first()
        return bool(expired_group in self.groups)

    def should_be_disabled(self):
        return bool(self.disable_on and datetime.now() > self.disable_on)

    def in_disabled_group(self):
        groupname = current_app.config['MFG_ACCOUNT_DISABLED_GROUPNAME']
        disabled_group = db.session.query(Group).filter(Group.groupname == groupname).first()
        return bool(disabled_group in self.groups)

    def managed_organizations(self):
        if self.is_admin:
            return db.session.query(Organization).all()

        return self.organizations

    def is_contact_person_for(self, organization):
        return bool(organization.id in [o.id for o in self.managed_organizations()])

    def can_manage(self, user):
        return bool(self.is_admin or self.is_contact_person_for(user.organization))

    def is_admin_or_contact_person(self):
        return bool(self.managed_organizations())

    def is_regular_user(self):
        return not bool(self.managed_organizations())

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def is_reusing_the_old_password(self, password):
        attrs = db.session.query(Radcheck).filter((Radcheck.username == self.username) &
                                                  (Radcheck.attribute.like("%-Password")) &
                                                  (Radcheck.op == ':=')).all()
        reused = False
        for attr in attrs:
            try:
                reused = check_password_hash(password, attr.value, attr.attribute)
                if reused:
                    break

            except ValueError:
                # TODO log => attr.attribute algorithm not implemented
                continue

        return reused


class Domain(db.Model, Base):
    __tablename__ = table_prefix + 'domain'

    id = db.Column(db.Integer, nullable=False, primary_key=True)
    domain_name = db.Column(db.String(253, 'utf8_bin'), unique=True, nullable=False)

    organizations = db.relationship('Organization', secondary=t_organization_domain, back_populates='domains')

    def __repr__(self):
        return f"<Domain {self.domain_name}>"


class Group(db.Model, Base):
    __tablename__ = table_prefix + 'group'

    id = db.Column(db.Integer, primary_key=True)
    groupname = db.Column(db.String(64, 'utf8_bin'), nullable=False, unique=True, index=True)
    radgroupcheck_attributes = db.relationship('Radgroupcheck', back_populates='group', passive_deletes=True)
    radgroupreply_attributes = db.relationship('Radgroupreply', back_populates='group', passive_deletes=True)
    users = db.relationship('User', back_populates='groups', secondary=t_radusergroup)

    organizations = db.relationship('Organization', secondary=t_organization_group, back_populates='groups')

    def __repr__(self):
        return f"<Group {self.groupname}>"


class ActionEnum(enum.Enum):
    reset = 0
    activate = 1


class Token(db.Model):
    __tablename__ = table_prefix + 'token'

    id = db.Column(db.Integer, nullable=False, primary_key=True)
    token = db.Column(db.String(32, 'utf8_bin'), unique=True, nullable=False)
    expires_on = db.Column(db.DateTime(timezone=True), nullable=False)
    action = db.Column(Enum(ActionEnum), nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey(table_prefix + 'user.id'), nullable=False)
    user = db.relationship("User", back_populates="tokens")

    def is_expired(self):
        return bool(self.expires_on < datetime.now())
        
    def reset_or_activate_url(self):
        return url_for('user.reset_or_activate', token=self.token, _external=True)


class SignupToken(db.Model):
    __tablename__ = table_prefix + 'signup_token'

    id = db.Column(db.Integer, nullable=False, primary_key=True)
    email = db.Column(db.String(253, 'utf8_bin'), unique=True, nullable=False)
    token = db.Column(db.String(32, 'utf8_bin'), unique=True, nullable=False)
    expires_on = db.Column(db.DateTime(timezone=True), nullable=False)

    def is_expired(self):
        return bool(self.expires_on < datetime.now())


class GlobalSettings(db.Model):
    __tablename__ = table_prefix + 'global_settings'

    id = db.Column(db.Integer, nullable=False, primary_key=True)
    keyword = db.Column(db.String(64, 'utf8_bin'), unique=True, nullable=False)
    value = db.Column(db.String(64, 'utf8_bin'), unique=False, nullable=False)


class OrganizationSettings(db.Model):
    __tablename__ = table_prefix + 'organization_settings'

    id = db.Column(db.Integer, nullable=False, primary_key=True)
    organization_id = db.Column(db.Integer,
                                db.ForeignKey(table_prefix + 'organization.id', ondelete='CASCADE'),
                                nullable=False)
    organization = db.relationship("Organization", back_populates="settings")
    keyword = db.Column(db.String(64, 'utf8_bin'), unique=False, nullable=False)
    value = db.Column(db.String(64, 'utf8_bin'), unique=False, nullable=False)


class WaitingForApproval(db.Model):
    __tablename__ = table_prefix + 'waiting_for_approval'

    id = db.Column(db.Integer, nullable=False, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey(table_prefix + 'organization.id'), nullable=True)
    organization = db.relationship("Organization", back_populates="waiting_for_approval")

    email = db.Column(db.String(253, 'utf8_bin'), nullable=False, unique=True)
    username = db.Column(db.String(64, 'utf8_bin'), nullable=False, unique=True, index=True)
    firstname = db.Column(db.String(64, 'utf8_bin'), nullable=False)
    lastname = db.Column(db.String(64, 'utf8_bin'), nullable=False)
    created_on = db.Column(db.Date, nullable=False, default=date.today)

    hash_type = db.Column(db.String(64, 'utf8_bin'), nullable=False)
    hash_value = db.Column(db.String(253, 'utf8_bin'), nullable=False)

    def domain(self):
        domain_name = self.email.split('@')[1].lower()
        domain_obj = db.session.query(Domain).filter(Domain.domain_name == domain_name).first()
        return domain_obj

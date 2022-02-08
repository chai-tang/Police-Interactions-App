import pytest
import sqlite3
from seleniumbase import BaseCase

from c499_test.conftest import base_url
from c499.backend import get_user
from c499.models import db, User

"""
This file defines all unit tests for the get_user backend method
"""

invalid_email = 'not_a_user@test.com'
invalid_name = 'mr new'
invalid_password = 'f'
valid_email = 'test_user@test.com'
valid_name = 'test user'
valid_password = 'Test123!'

class BackendMethodTest(BaseCase):

    def test_get_user(self, *_):
        """
        **Test backend method get_user**

        Mocking:
        None

        Actions:
        - validate that an email with no existing user returns None
        - open /logout (to invalidate any logged-in sessions that may exist)
        - open /register
        - register new user
        - validate if the two emails are returning existing users
        - delete user

        """

        # validate that get_user() does not return a user if the new_email does not yet belong to a user
        assert get_user(invalid_email) is None
        assert get_user(valid_email) is None

        # open /logout
        self.open(base_url + '/logout')
        # open /register
        self.open(base_url + '/register')

        # enter new user's info into the appropriate forms
        self.type("#email", valid_email)
        self.type("#name", valid_name)
        self.type('#password', valid_password)
        self.type('#password2', valid_password)

        # submit the forms
        self.click('input[type="submit"]')

        # Validate get_user(). One should return a user. The other should return None
        assert get_user(valid_email) is not None
        assert get_user(invalid_email) is None

        #must remove this user from db.sqlite in order to run test again
        new_user = User.query.filter_by(email=valid_email).first()
        db.session.delete(new_user)
        db.session.commit()

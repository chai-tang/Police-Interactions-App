import pytest
from seleniumbase import BaseCase
from c499.models import db, User

from c499_test.conftest import base_url


# integration testing: the test case interacts with the 
# browser, and test the whole system (frontend+backend).

@pytest.mark.usefixtures('server')
class Registered(BaseCase):

    def register(self):
        """Register a new user"""
        self.open(base_url + '/register')
        self.type("#email", "testregisterint@email")
        self.type("#name", "tester")
        self.type("#password", "qqQQ!!")
        self.type("#password2", "qqQQ!!")
        self.click('input[type="submit"]')

    def login(self):
        """Login with test user credentials"""
        self.open(base_url + '/login')
        self.type("#email", "testregisterint@email")
        self.type("#password", "qqQQ!!")
        self.click('input[type="submit"]')

    def logout(self):
        """Logout the user"""
        self.open(base_url+'/logout')

    def test_register_login(self):
        """Test registration, login and logout, then delete the user"""
        self.register()
        self.login()
        self.open(base_url)
        self.assert_element("#welcome_header")
        self.logout()
        current_url = self.driver.current_url
        self.assert_equal(current_url,base_url+'/login')

        new_user = User.query.filter_by(email="testregisterint@email").first()
        db.session.delete(new_user)
        db.session.commit()

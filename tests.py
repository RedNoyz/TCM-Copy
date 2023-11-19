import unittest
from flask import Flask
from flask_testing import TestCase
from flask_login import login_user
from flask_app import app, db, TestSuites, Projects, Users, TestCases, FeatureList
from flask_login import current_user, UserMixin
from unittest.mock import patch

class MockUser(UserMixin):
    def __init__(self, username):
        self.username = username

class TestCreateSuiteRoute(TestCase):
    def create_app(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'  # Use an in-memory database for testing
        return app

    def setUp(self):
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    @patch('flask_login.current_user', MockUser('test1'))
    def test_create_suite_route(self):
        # Create a test project for testing
        test_user = Users(username='test1', password='test_password', first_name='testname', last_name='testname', email='testemail@test.yo')  # Replace with your actual user creation logic
        db.session.add(test_user)
        db.session.commit()

        login_user(test_user)
        test_project = Projects(id=1, project_name="Test Project")
        db.session.add(test_project)
        db.session.commit()

        test_suite = TestSuites(id=1, test_suites_name='testsuite', test_suites_description='test-description', project_id=1)
        db.session.add(test_suite)
        db.session.commit()

        response = self.client.post('/projects/project/1/test-suites/create-suite', data={
            'test_suites_name': 'Test Suite 1',
            'test_suites_description': 'Description for Test Suite 1'
        })

        # Assert that the response redirects to the correct URL
        self.assertIn('/projects/project/1/test-suites', response.location)

        # Assert that the TestSuites table has one entry
        self.assertEqual(TestSuites.query.count(), 1)

        # Add more assertions based on your application's logic

if __name__ == '__main__':
    unittest.main()
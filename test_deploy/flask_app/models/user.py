#import the function that will return instance of connection
from flask_app.config.mysqlconnection import MySQLConnection, connectToMySQL
from flask_app import app
#import the function that will hash passwords and check hashed passwords against inputs
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)
from flask import flash, session
import re

#model class after the table from database
class User:
    db = 'users_schema'

    def __init__( self, data ):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']

# MODELS - CREATE
    @classmethod
    def register_user(cls, data):
        if not cls.validate_user_registration(data):
            return False

        parsed_data = cls.parse_registration_data(data)
        query = """
        INSERT INTO users(first_name, last_name, email, password)
        VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s)
        ;"""

        user_id = connectToMySQL(cls.db).query_db(query, parsed_data)
        session['user_id'] = user_id
        session['user_name'] = f"{parsed_data['first_name']} {parsed_data['last_name']}"
        return True
# MODELS - READ

    @classmethod
    def get_user_by_email(cls, email):
        data = {'email' : email}
        query = """
        SELECT *
        FROM users
        WHERE email = %(email)s
        ;"""

        result = connectToMySQL(cls.db).query_db(query, data)
        if result:
            result = cls(result[0])
        return result

    @classmethod
    def get_user_by_id(cls, id):
        data = {'id' : id}
        query = """
        SELECT *
        FROM users
        WHERE id = %(id)s
        ;"""

        result = connectToMySQL(cls.db).query_db(query, data)
        if result:
            result = cls(result[0])
        return result
    
    @classmethod
    def get_all_users(cls):
        query = """
        SELECT *
        FROM users
        ;"""

        result = connectToMySQL(cls.db).query_db(query)
        all_users = []
        for user in result:
            all_users.append(cls(user))
        return all_users

# MODELS - UPDATE
# MODELS - DELETE
# MODELS - VALIDATION
    @staticmethod
    def validate_user_registration(data):
        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
        is_valid = True
        if len(data['first_name']) < 2:
            flash('Your first name must be at least two characters long.', 'error')
            is_valid = False
        if len(data['last_name']) < 2:
            flash('Your last name must be at least two characters long.', 'error')
            is_valid = False
        if not EMAIL_REGEX.match(data['email']):
            flash('Email address is invalid.', 'error')
            is_valid = False
        if User.get_user_by_email(data['email'].lower()):
            flash('That email is already in use.', 'error')
            is_valid = False
        if len(data['password']) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            is_valid = False
        if re.search("[0-9]", data['password']) == None:
            flash('You password must contain at least one number.', 'error')
            is_valid = False
        if re.search("[A-Z]", data['password']) == None:
            flash('Password must contain at least 1 uppercase character.', 'error')
            is_valid = False
        if data['password'] != data['confirm_password']:
            flash('Your passwords do not match.', 'error')
            is_valid = False
        return is_valid

    @staticmethod
    def parse_registration_data(data):
        parsed_data = {}
        parsed_data['first_name'] = data['first_name']
        parsed_data['last_name'] = data['last_name']
        parsed_data['email'] = data['email'].lower()
        parsed_data['password'] = bcrypt.generate_password_hash(data['password'])
        return parsed_data

    @staticmethod
    def login(data):
        this_user = User.get_user_by_email(data['email'].lower())
        if this_user:
            if bcrypt.check_password_hash(this_user.password, data['password']):
                session['user_id'] = this_user.id
                return True
        flash('Your login information is incorrect.', 'login')
        return False
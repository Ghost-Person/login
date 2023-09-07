from flask_app.config.mysqlconnection import connectToMySQL
import re
from flask import flash
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

class User:
    db = "login_db"
    def __init__(self,data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']
    
    @classmethod
    def add_user(cls,data):
        query = "INSERT INTO users (first_name, last_name, email, password) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s);"
        return connectToMySQL(cls.db).query_db(query,data)
    
    @classmethod
    def all_users(cls):
        query = "SELECT * FROM users;"
        result = connectToMySQL(cls.db).query_db(query)
        users = []
        for row in result:
            users.append(cls(row) )
        return users
    
    @classmethod
    def user_by_id(cls,data):
        query = "SELECT * FROM users WHERE id = %(id)s;"
        result = connectToMySQL(cls.db).query_db(query,data)
        return cls(result[0])
    
    @classmethod
    def user_by_email(cls,data):
        query = "SELECT * FROM users WHERE email = %(email)s;"
        result = connectToMySQL(cls.db).query_db(query,data)
        if len(result) < 1:
            return False
        return cls(result[0])
    
    @staticmethod
    def validate(user):
        is_valid = True
        query = "SELECT * FROM users WHERE email = %(email)s;"
        results = connectToMySQL(User.db).query_db(query,user)
        if len(results) >= 1:
            flash("That Email is taken.")
            is_valid = False
        if not EMAIL_REGEX.match(user['email']):
            flash("Invalid Email.")
            is_valid = False
        if len(user['first_name']) < 2:
            flash("First name must be at least 2 characters")
            is_valid = False
        if len(user['last_name']) < 2:
            flash("Last name must be at least 2 characters")
            is_valid = False
        if len(user['password']) < 8:
            flash("Password must be at least 8 characters")
            is_valid = False
        if user['password'] != user['confirm']:
            flash("Passwords do not match.")
            is_valid = False
        return is_valid
    


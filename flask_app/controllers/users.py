from flask import render_template, redirect, request, session, flash
from flask_app import app
from flask_app.models.user import User
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

@app.route('/')
def home():
    return render_template('reg_login.html')

@app.route('/register', methods = ['POST'])
def register():
    if not User.validate(request.form):
        return redirect('/')
    data = {
        "first_name": request.form['first_name'],
        "last_name": request.form['last_name'],
        "email": request.form['email'],
        "password": bcrypt.generate_password_hash(request.form['password'])
    }
    id = User.add_user(data)
    session['user_id'] = id

    return redirect('/welcome')

@app.route('/login', methods=['POST'])
def login():
    user = User.user_by_email(request.form)
    if not user:
        flash("We don't recognize this email.")
        return redirect('/')
    if not bcrypt.check_password_hash(user.password, request.form['password']):
        flash("Password incorrect.")
        return redirect('/')
    session['user_id'] = user.id
    return redirect('/welcome')


@app.route('/welcome')
def welcome_page():
    if 'user_id' not in session:
        return redirect('/logout')
    data = {
        'id': session['user_id']
    }
    return render_template("welcome.html", user=User.user_by_id(data))
    

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

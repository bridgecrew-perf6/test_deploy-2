from flask_app import app
from flask import render_template, request, session, redirect, flash
from flask_app.models import user, sighting

#CONTROLLERS - CREATE
@app.route('/users/registration', methods = ['POST'])
def register_user():
    if user.User.register_user(request.form):
        return redirect('/users/dashboard')
    return redirect('/')

#CONTROLLERS - READ
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/users/dashboard')
def user_dashboard():
    if 'user_id' not in session:
        return redirect('/')
    this_user = user.User.get_user_by_id(session['user_id'])
    all_users = user.User.get_all_users()
    all_sightings = sighting.Sighting.get_all_sightings()

    return render_template('dashboard.html', this_user = this_user, all_users = all_users, all_sightings = all_sightings)

@app.route('/users/logout')
def user_logout():
    session.clear()
    return redirect('/')

@app.route('/users/login', methods = ['POST'])
def user_login():
    if user.User.login(request.form):
        return redirect('/users/dashboard')
    return redirect('/')
#CONTROLLERS - UPDATE
#CONTROLLERS - DELETE
from c499 import app
from flask_sqlalchemy import SQLAlchemy

"""
This file defines all models used by the server
These models provide us a object-oriented access
to the underlying database, so we don't need to 
write SQL queries such as 'select', 'update' etc.
"""


db = SQLAlchemy()
db.init_app(app)

class User(db.Model):
    """
    A user model which defines the sql table
    """
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

class IncidentReport(db.Model):
    """
    A model that defines the sql table for a user submitted incident report
    """
    id = db.Column(db.Integer, primary_key=True) # unique incident ID
    user_id = db.Column(db.Integer) # user ID of the whoever submitted the report
    latitude = db.Column(db.Float) 
    longitude = db.Column(db.Float) 
    date_time = db.Column(db.DateTime)    
    description = db.Column(db.Text)
    plates = db.Column(db.Text)
    name = db.Column(db.Text)
    badge = db.Column(db.Text)
    profile = db.Column(db.Text)
    filenames = db.Column(db.String)

# it creates all the SQL tables if they do not exist
with app.app_context():
    db.create_all()
    db.session.commit()

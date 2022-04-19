from c499.models import db, User, IncidentReport
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import desc, func
from datetime import datetime

"""
This file defines all backend logic that interacts with database and other services
"""


def get_user(email):
    """
    Get a user by a given email
    :param email: the email of the user
    :return: a user that has the matched email address
    """
    user = User.query.filter_by(email=email).first()
    return user


def login_user(email, password):
    """
    Check user authentication by comparing the password
    :param email: the email of the user
    :param password: the password input
    :return: the user if login succeeds
    """
    # if this returns a user, then the name already exists in database
    user = get_user(email)
    if not user or not check_password_hash(user.password, password):
        return None
    return user


def register_user(email, name, password, password2):
    """
    Register the user to the database
    :param email: the email of the user
    :param name: the name of the user
    :param password: the password of user
    :param password2: another password input to make sure the input is correct
    :return: an error message if there is any, or None if register succeeds
    """
    hashed_pw = generate_password_hash(password, method='sha256')
    # Store the encrypted password rather than the plain password
    new_user = User(email=email, name=name, password=hashed_pw)

    db.session.add(new_user)
    db.session.commit()
    return None

def upload_report(user_id,description,longitude,latitude,plates,name,badge,profile,filenames,incident_type,private_description):
    """
    Uploads a user incident report to the database
    :param user: the user making the report
    :param description: the user's text description of the incident
    :param longitude: the longitude of the incident's location
    :param latitude: the latitude of the incident's location
    :param filenames: the names of the of files uploaded with the report (after being uploaded to the server)
    :param incident_type: the selected incident types (string)
    :param private_description: the user's private text description of the incident
    :return: an error message if there is any, or None if the report upload succeeds
    """

    incident=IncidentReport(user_id=user_id,description=description,longitude=longitude,latitude=latitude,plates=plates,name=name,badge=badge,profile=profile,date_time=datetime.now(),filenames=filenames,incident_type=incident_type,private_description=private_description)
    db.session.add(incident)
    db.session.commit()
    return None

def get_latest_report_id():
    """
    Retrieves the current highest report ID
    """
    highest_id = db.session.query(func.max(IncidentReport.id)).scalar()
    if (highest_id) != None:
        return highest_id
    else:
        return 0

def get_all_reports():
    """
    Retrieves a list of all currently recorded reports in the database
    """
    return IncidentReport.query.all()

def get_user_reports(user):
    """
    Retrieves a list of all currently recorded reports in the database that were uploaded by the given user
    """
    return IncidentReport.query.filter_by(user_id=user.id)
from email.policy import default
import flask
from flask import Flask, redirect, request, url_for
import random
import time
import requests
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import sshtunnel
import mysql.connector
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_ckeditor import CKEditor
from flask_ckeditor import CKEditorField
import os


app = Flask(__name__)
ckeditor = CKEditor(app)

tunnel = sshtunnel.SSHTunnelForwarder(
    ('ssh.eu.pythonanywhere.com'), ssh_username=os.getenv("qa_hub_username"), ssh_password=os.getenv("qa_hub_password"), remote_bind_address=('rednoyzdev.mysql.eu.pythonanywhere-services.com', 3306)
)
tunnel.start()
# Add database From local
SQLALCHEMY_DATABASE_URI = "mysql://{username}:{password}@{hostname}:{port}/{databasename}".format(
    username=os.getenv("qa_hub_username"),
    password=os.getenv("qa_hub_password"),
    hostname="127.0.0.1",
    port=tunnel.local_bind_port,
    databasename="rednoyzdev$qa-hub",
    )
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config['SECRET_KEY'] = 'muiecucacatcheie'

# # Add database Live
# SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
#     username=os.getenv("qa_hub_username"),
#     password=os.getenv("qa_hub_password"),
#     hostname="rednoyzdev.mysql.eu.pythonanywhere-services.com",
#     databasename="rednoyzdev$qa-hub",
# )
# app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
# app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
# app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# # Secret key
# app.config['SECRET_KEY'] = 'muiecucacatcheie'
# Init DB
db = SQLAlchemy(app)

copyright_year = time.strftime("%Y")

# -------------------------------------- PROJECTS CLASS ----------------------------------------- #
class Projects(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    project_name = db.Column(db.String(), nullable=False)
    project_is_archived = db.Column(db.Boolean(), nullable=False, default=False)
    created_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())
    archived_date = db.Column(db.DateTime, nullable=True)

# --------------------------------- CREATE PROJECT FORM CLASS ----------------------------------- #
class CreateProjectForm(FlaskForm):
    project_name = StringField("Create New Project", validators=[DataRequired()])
    submit = SubmitField("Create")

# ---------------------------------------- HOME PAGE -------------------------------------------- #
@app.route('/')
def home_page():
    return flask.render_template('home_page.html',
                                 year=copyright_year
                                 )

# -------------------------------------- PROJECTS PAGE ------------------------------------------ #
@app.route(rule='/projects')
def projects():
    project_list = Projects.query.order_by(Projects.id)
    return flask.render_template(template_name_or_list='projects.html',
                                 year=copyright_year,
                                 project_list=project_list
                                 )


# -------------------------------- SELECTED PROJECT PAGE ---------------------------------------- #
@app.route('/projects/project/<int:id>')
def project(id):
    project = Projects.query.order_by(Projects.id)
    return flask.render_template(template_name_or_list='project_page.html',
                                 project=project,
                                 id=id)


# ---------------------------------- CREATE PROJECT PAGE ---------------------------------------- #
@app.route(rule='/projects/create-project', methods=['GET', 'POST'])
def create_project():
    form = CreateProjectForm()
    form.project_name.data = "Insert Project Name"
    if request.method == 'POST':
        if form.validate_on_submit():
            project = Projects(project_name=form.project_name.data)
            db.session.add(project)
            db.session.commit()
        return redirect('/projects')
    return flask.render_template(template_name_or_list='create_project.html',
                                 year=copyright_year,
                                 form=form)





if __name__ == "__main__":
    app.run(debug=True)
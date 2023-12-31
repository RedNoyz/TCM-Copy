import flask
from flask import Flask, redirect, request, url_for, flash, jsonify
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import time
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from datetime import datetime
import sshtunnel
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField, SelectField, SelectFieldBase
from wtforms.validators import DataRequired
from flask_ckeditor import CKEditor
from flask_ckeditor import CKEditorField


app = Flask(import_name=__name__)
ckeditor = CKEditor(app=app)

tunnel = sshtunnel.SSHTunnelForwarder(
    ssh_address_or_host=('ssh.eu.pythonanywhere.com'), 
    ssh_username='rednoyzdev',
    ssh_password='aurLA11!!',
    remote_bind_address=('rednoyzdev.mysql.eu.pythonanywhere-services.com', 3306)
)
tunnel.start()
# Add database From local
SQLALCHEMY_DATABASE_URI = "mysql://{username}:{password}@{hostname}:{port}/{databasename}".format(
    username='rednoyzdev',
    password='aurLA11!!',
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

# Flask_Login Stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)

@login_manager.user_loader
def load_user(id):
	return Users.query.get(int(id))

copyright_year = time.strftime("%Y")

# -------------------------------------- PROJECTS CLASS ----------------------------------------- #
class Projects(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    project_name = db.Column(db.String(100), nullable=False)
    project_is_archived = db.Column(db.Boolean(), nullable=False, default=False)
    created_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())
    archived_date = db.Column(db.DateTime, nullable=True)

# --------------------------------- CREATE PROJECT FORM CLASS ----------------------------------- #
class CreateProjectForm(FlaskForm):
    project_name = StringField("Create New Project", validators=[DataRequired()])
    submit = SubmitField("Create")

# ---------------------------------- LOGIN AND SIGNUP CLASSES ----------------------------------- #
class CreateNewUserForm(FlaskForm):
    username = StringField(label="Username", validators=[DataRequired()])
    first_name = StringField(label="First Name", validators=[DataRequired()])
    last_name = StringField(label="Last Name", validators=[DataRequired()])
    email = StringField(label="Email", validators=[DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    submit = SubmitField(label="Create")

class LoginExistingUserForm(FlaskForm):
    username = StringField(label="Username", validators=[DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    submit = SubmitField(label="Login")

# -------------------------------------- USERS CLASS -------------------------------------------- #
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    username = db.Column(db.String(100), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(999), nullable=False)
    created_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())
    user_is_admin = db.Column(db.Boolean(), nullable=False, default=False)
    role_id = db.Column(db.Integer, nullable=False, default=0)

# ------------------------------------- TEST SUITES CLASS --------------------------------------- #
class TestSuites(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    test_suites_name = db.Column(db.String(100), nullable=False)
    test_suites_description = db.Column(db.String(999), nullable=False)
    project_id = db.Column(db.Integer, nullable=False)
    test_suites_archived = db.Column(db.Boolean, nullable=False, default=False)
    created_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())

class CreateNewTestSuite(FlaskForm):
    test_suites_name = StringField(label="Test Suite Name", validators=[DataRequired()])
    test_suites_description = StringField(label="Test Suite Description", validators=[DataRequired()])
    submit = SubmitField(label="Create Test Suite")

# --------------------------------- ---- TEST CASES CLASS --------------------------------------- #
class TestCases(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    test_case_title = db.Column(db.String(100), nullable=False)
    test_case_body = db.Column(db.String(999), nullable=False)
    test_case_preconditions = db.Column(db.String(999), nullable=False)
    project_id = db.Column(db.Integer, nullable=False)
    suite_id = db.Column(db.Integer, nullable=False)
    test_case_author = db.Column(db.Integer, nullable=False)
    test_case_feature = db.Column(db.Integer, nullable=False)
    test_case_custom_fields = db.Column(db.JSON)
    test_case_created_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())
    test_case_updated_date = db.Column(db.DateTime)
    section_id = db.Column(db.Integer)

class CreateNewTestCase(FlaskForm):
    test_case_title = StringField(label="Test Case Title", validators=[DataRequired()])
    test_case_body = CKEditorField(label="Test Case Description", validators=[DataRequired()])
    test_case_preconditions = CKEditorField(label="Test Case Preconditions", validators=[DataRequired()])
    test_case_feature = SelectField(label="Select Feature",validators=[DataRequired()])
    test_section = SelectField(label="Select Section",validators=[DataRequired()])
    submit = SubmitField(label="Create Test Case")

# --------------------------------- ---- TEST CASES CLASS --------------------------------------- #
class FeatureList(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    feature = db.Column(db.String(45), nullable=False)
    project_id = db.Column(db.Integer, nullable=False)

class CreateNewFeatureForm(FlaskForm):
    feature = StringField(label="Feature Name", validators=[DataRequired()])
    submit = SubmitField(label="Create Feature")

class TestSection(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    section_name = db.Column(db.String(100), nullable=False)
    test_suite_id = db.Column(db.Integer, nullable=False)
    order_rank = db.Column(db.Integer)

class CreateNewSectionForm(FlaskForm):
    section_name = StringField(label="Section Name", validators=[DataRequired()])
    submit = SubmitField(label="Create Section")

# ------------------------------------- TEST RUNS CLASSES --------------------------------------- #
class TestRuns(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    test_run_name = db.Column(db.String(100), nullable=False)
    test_suite_id = db.Column(db.Integer, nullable=False)
    project_id = db.Column(db.Integer, nullable=False)
    created_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())

class CreateNewTestRunForm(FlaskForm):
    test_run_name = StringField(label="Test Run Name", validators=[DataRequired()])
    test_suite_selection = SelectField(label="Select Test Suite",validators=[DataRequired()])
    submit = SubmitField(label="Create Test Run")

class TestResults(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    test_case_id = db.Column(db.Integer, nullable=False)
    test_status_id = db.Column(db.Integer, nullable=False)
    test_run_id = db.Column(db.Integer, nullable=False)
    test_suite_id = db.Column(db.Integer, nullable=False)
    project_id = db.Column(db.Integer, nullable=False)
    date_tested = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())

class Statuses(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    status_name = db.Column(db.String(100), nullable=False)

# ---------------------------------------- HOME PAGE -------------------------------------------- #
@app.route(rule='/')
def home_page():
    user = 'Not Logged In'
    if current_user.is_authenticated:
        user = current_user.username
        
    return flask.render_template(template_name_or_list='home_page.html',
                                 year=copyright_year,
                                 user=user
                                 )

# --------------------------------------- LOGIN PAGE -------------------------------------------- #
@app.route(rule='/login', methods=['GET', 'POST'])
def login():
    form = LoginExistingUserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(pw_hash=user.password, 
                                          password=form.password.data):
                login_user(user=user)
                flash(message="Login Succesfull!!")

                return redirect(location=url_for(endpoint='projects'))
            
            else:
                flash(message="Wrong Password - Try Again!")
        else:
            flash(message="That User Doesn't Exist! Try Again...")

    return flask.render_template(template_name_or_list='login_page.html',
                                 form=form,
                                 year=copyright_year)

# -------------------------------------- SIGN-UP PAGE ------------------------------------------- #
@app.route(rule='/sign-up', methods=['GET', 'POST'])
def sign_up():
    form = CreateNewUserForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(password=form.password.data).decode(encoding='utf-8')
        user = Users(username=form.username.data,
                     first_name=form.first_name.data, 
                     last_name=form.last_name.data, 
                     email=form.email.data, 
                     password=hashed_pw)
        db.session.add(instance=user)
        db.session.commit()
        flash(message="User Added Successfully!")
        return redirect(location='/login')
    else:
        flash(message="Please make sure to complete all the fields!")
    return flask.render_template(template_name_or_list='signup_page.html',
                                 form=form,
                                 year=copyright_year)

# ----------------------------------------- LOGOUT ---------------------------------------------- #
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
	logout_user()
	flash("You Have Been Logged Out! Thanks For Stopping By...")
	return redirect(url_for('home_page'))

# ---------------------------------------- ADMIN PAGE ------------------------------------------- #
@app.route('/admin')
@login_required
def admin():
    username = current_user.username
    if current_user.user_is_admin is True:
        return flask.render_template("admin.html",
                                     user=username)
    else:
        flash("Sorry you must be the Admin to access the Admin Page...")
        return flask.redirect(url_for('home_page'))




# -------------------------------------- PROJECTS PAGE ------------------------------------------ #
@app.route(rule='/projects')
@login_required
def projects():
    user = current_user.username
    project_list = Projects.query.order_by(Projects.id)
    return flask.render_template(template_name_or_list='projects.html',
                                 year=copyright_year,
                                 project_list=project_list,
                                 user=user
                                 )

# -------------------------------- SELECTED PROJECT PAGE ---------------------------------------- #
@app.route(rule='/projects/project/<int:project_id>')
@login_required
def project(project_id):
    user = current_user.username
    project = Projects.query.filter_by(id=project_id).one()

    return flask.render_template(template_name_or_list='project_page.html',
                                 project=project,
                                 project_id=project_id,
                                 user=user,
                                 year=copyright_year)

# ---------------------------------- CREATE PROJECT PAGE ---------------------------------------- #
@app.route(rule='/projects/create-project', methods=['GET', 'POST'])
@login_required
def create_project():
    user = current_user.username
    form = CreateProjectForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            project = Projects(project_name=form.project_name.data)
            db.session.add(project)
            db.session.commit()
        return redirect('/projects')
    return flask.render_template(template_name_or_list='create_project.html',
                                 year=copyright_year,
                                 form=form,
                                 user=user)

# ------------------------------------ TEST SUITES PAGE ----------------------------------------- #
@app.route(rule='/projects/project/<int:project_id>/test-suites')
@login_required
def test_suites(project_id):
    user = current_user.username
    project = Projects.query.filter_by(id=project_id).one()

    test_suites_list = TestSuites.query.filter_by(project_id=project_id).all()

    return flask.render_template(template_name_or_list='test_suites.html',
                                 project=project,
                                 project_id=project_id,
                                 user=user,
                                 test_suites_list=test_suites_list)

# ---------------------------------- CREATE SUITE PAGE ------------------------------------------ #
@app.route(rule='/projects/project/<int:project_id>/test-suites/create-suite', methods=['GET', 'POST'])
@login_required
def create_suite(project_id):
    user = current_user.username
    project = Projects.query.filter_by(id=project_id).one()
    form = CreateNewTestSuite()

    if request.method == 'POST':
        if form.validate_on_submit():
            test_suite = TestSuites(test_suites_name=form.test_suites_name.data,
                                    test_suites_description=form.test_suites_description.data,
                                    project_id=project_id)
            db.session.add(test_suite)
            db.session.commit()
        return redirect(f'/projects/project/{project_id}/test-suites')

    return flask.render_template(template_name_or_list='create_test_suite.html',
                                 project=project,
                                 project_id=project_id,
                                 user=user,
                                 form=form,
                                 )
# ---------------------------------- SELECT SUITE PAGE ------------------------------------------ #
@app.route(rule='/projects/project/<int:project_id>/test-suites/<int:suite_id>', methods=['GET', 'POST'])
@login_required
def test_suite_page(project_id, suite_id):

    if request.method == 'POST':
        try:
            data = request.get_json()

            test_case_id = data.get('test_case_id')
            target_section_id = data.get('target_section_id')

            test_case = TestCases.query.get(test_case_id)
            print(f"Received test_case_id: {test_case_id}, target_section_id: {target_section_id}")
            if test_case:
                test_case.section_id = target_section_id
                db.session.commit()

                return jsonify({'success': True})
            else:
                return jsonify({'success': False, 'error': 'Test case not found'})

        except Exception as e:
            print(f"Error: {str(e)}")
            return jsonify({'success': False, 'error': str(e)})

    user = current_user.username
    suite = TestSuites.query.filter_by(id=suite_id, project_id=project_id).one()
    loop_counter = 0
    test_cases_list = TestCases.query.filter_by(suite_id=suite_id).all()
    features = FeatureList.query.filter_by(project_id=project_id).all()
    users = Users.query.order_by(Users.id).all()
    section_list = TestSection.query.filter_by(test_suite_id=suite_id).all()

    features_dic = {}
    for item in features:
        features_dic[item.id] = item.feature

    users_dic = {}
    for item in users:
        users_dic[item.id] = item.username

    return flask.render_template(template_name_or_list='test_suite_page.html',
                                 suite_id=suite_id,
                                 project_id=project_id,
                                 user=user,
                                 users=users,
                                 suite=suite,
                                 test_cases_list=test_cases_list,
                                 features=features,
                                 loop_counter=loop_counter,
                                 features_dic=features_dic,
                                 users_dic=users_dic,
                                 year=copyright_year,
                                 section_list=section_list)

# ------------------------------ CREATE TEST CASE PAGE ------------------------------------------ #
@app.route(rule='/projects/project/<int:project_id>/test-suites/<int:suite_id>/create-test-case', methods=['GET', 'POST'])
@login_required
def create_test_case(project_id, suite_id):
    user = current_user.username    
    form = CreateNewTestCase()
    feature_list = FeatureList.query.filter_by(project_id=project_id).all()
    form.test_case_feature.choices = [("-", "-")] + [(str(feature.id), feature.feature) for feature in feature_list]

    section_list = TestSection.query.filter_by(test_suite_id=suite_id).all()
    form.test_section.choices = [("-", "-")] + [(str(section.id), section.section_name) for section in section_list]

    if request.method == 'POST':
        if (form.test_case_feature.data == "-" or form.test_section.data == "-"):
            flash("Please Select A Feature and A Section!!")
        else:
            if form.validate_on_submit():
                print(form.data)
                test_case = TestCases(test_case_title=form.test_case_title.data,
                                    test_case_body=form.test_case_body.data,
                                    test_case_preconditions=form.test_case_preconditions.data,
                                    test_case_author=current_user.id,
                                    project_id=project_id,
                                    suite_id=suite_id,
                                    test_case_feature=form.test_case_feature.data,
                                    section_id=form.test_section.data
                                    )
                db.session.add(test_case)
                db.session.commit()
                return redirect(f'/projects/project/{project_id}/test-suites/{suite_id}')
            else:
                print(form.errors)

    return flask.render_template(template_name_or_list='create_test_case.html',
                                 project_id=project_id,
                                 suite_id=suite_id,
                                 form=form,
                                 user=user)

# -------------------------------- CREATE FEATURE PAGE ------------------------------------------ #
@app.route(rule='/projects/project/<int:project_id>/test-suites/create-feature', methods=['GET', 'POST'])
@login_required
def create_feature(project_id):
    form = CreateNewFeatureForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            feature = FeatureList(feature=form.feature.data,
                                    project_id=project_id)
            db.session.add(feature)
            db.session.commit()
            return redirect(f'/projects/project/{project_id}/test-suites')
        
    return flask.render_template(template_name_or_list='create_feature.html',
                                 project_id=project_id,
                                 form=form)

# ------------------------------------ CREATE SECTION ------------------------------------------- #
@app.route(rule='/projects/project/<int:project_id>/test-suites/<int:suite_id>/create-section', methods=['GET', 'POST'])
@login_required
def create_section(project_id, suite_id):
    user = current_user.username    

    form = CreateNewSectionForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            section = TestSection(section_name=form.section_name.data,
                              test_suite_id=suite_id)
            db.session.add(section)
            db.session.commit()
            return redirect(f'/projects/project/{project_id}/test-suites/{suite_id}')
        
    return flask.render_template(template_name_or_list='create_section.html',
                                 project_id=project_id,
                                 suite_id=suite_id,
                                 form=form,
                                 user=user)


# ------------------------------------ TEST CASE PAGE ------------------------------------------- #
@app.route(rule='/projects/project/<int:project_id>/test-suites/<int:suite_id>/test-case/<int:testcase_id>', methods=['GET', 'POST'])
@login_required
def view_test_case(project_id, suite_id, testcase_id):
    user = current_user.username
    user_role = current_user.role_id

    test_case = TestCases.query.filter_by(id=testcase_id, project_id=project_id, suite_id=suite_id).one()

    print(test_case.test_case_title)

    if user_role <= 3:
        return flask.render_template(template_name_or_list='test_case_page.html',
                                     project_id=project_id,
                                    suite_id=suite_id,
                                    testcase_id=testcase_id,
                                    user=user,
                                    test_case=test_case)
    else:
        return flask.render_template(template_name_or_list='test_case_page_edit.html',
                                     project_id=project_id,
                                    suite_id=suite_id,
                                    testcase_id=testcase_id,
                                    user=user,
                                    test_case=test_case)

# ------------------------------------ TEST RUNS PAGE ------------------------------------------- #
@app.route(rule='/projects/project/<int:project_id>/test-runs')
@login_required
def test_runs(project_id):
    user = current_user.username
    project = Projects.query.filter_by(id=project_id).one()

    test_runs_list = TestRuns.query.filter_by(project_id=project_id).order_by(TestRuns.id.desc()).all()

    test_results_count = db.session.query(
            TestResults.test_run_id,
            TestResults.test_status_id,
            func.count().label('count')
        ).group_by(
            TestResults.test_run_id,
            TestResults.test_status_id
        ).all()
  
    statuses = Statuses.query.order_by(Statuses.id).all()
    statuses_dic = {}
    for item in statuses:
        statuses_dic[item.id] = item.status_name

    return flask.render_template(template_name_or_list='test_runs.html',
                                 project=project,
                                 project_id=project_id,
                                 user=user,
                                 test_runs_list=test_runs_list,
                                 test_results_count=test_results_count,
                                 statuses_dic=statuses_dic,
                                 year=copyright_year)


# -------------------------------- CREATE TEST RUN PAGE ----------------------------------------- #
@app.route(rule='/projects/project/<int:project_id>/test-runs/create-run', methods=['GET', 'POST'])
@login_required
def create_run(project_id):
    user = current_user.username
    test_suites_list = TestSuites.query.filter_by(project_id=project_id).all()

    form = CreateNewTestRunForm()

    form.test_suite_selection.choices = [("-", "-")] + [(str(section.id), section.test_suites_name) for section in test_suites_list]
    if request.method == 'POST':
        try:
            if form.validate_on_submit():
                new_run = TestRuns(test_run_name=form.test_run_name.data,
                                test_suite_id=form.test_suite_selection.data,
                                project_id=project_id)
                db.session.add(new_run)
                db.session.commit()
            

                test_cases_list = TestCases.query.filter_by(project_id=project_id, suite_id=form.test_suite_selection.data).all()
                print(test_cases_list)

                test_run_id = TestRuns.query.filter_by(project_id=project_id).order_by(TestRuns.id.desc()).first()

                for test_case in test_cases_list:
                    result = TestResults(test_status_id=1,
                                        test_case_id=test_case.id,
                                        test_suite_id=form.test_suite_selection.data,
                                        project_id=project_id,
                                        test_run_id=test_run_id.id)
                    db.session.add(result)
                    db.session.commit()

            return redirect(f'/projects/project/{project_id}/test-runs')
        
        except Exception as e:
            print(f"Error: {str(e)}")

    return flask.render_template(template_name_or_list='create_run.html',
                                 project_id=project_id,
                                 user=user,
                                 form=form)
# ------------------------------------ TEST RUN PAGE -------------------------------------------- #
@app.route(rule='/projects/project/<int:project_id>/test-runs/<int:test_run_id>', methods=['GET', 'POST'])
@login_required
def test_run_page(project_id, test_run_id):
    user = current_user.username

    return flask.render_template(template_name_or_list='test_run_page.html',
                                 project_id=project_id,
                                 test_run_id=test_run_id,
                                 user=user,
                                 year=copyright_year)

# ------------------------------------ SOCIALS PAGE --------------------------------------------- #
@app.route(rule='/socials')
def socials():
    return flask.render_template(template_name_or_list='socials_page.html')

if __name__ == "__main__":
    app.run(debug=True)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, FloatField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from models import User, Student, Department, Program

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    matricule = StringField('Matricule', validators=[DataRequired(), Length(min=2, max=50)])
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=150)])
    phone = StringField('Phone Number', validators=[DataRequired(), Length(min=7, max=20)])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired(), Length(min=5, max=300)])
    parent_contact = StringField('Parent Contact', validators=[DataRequired(), Length(min=7, max=100)])
    department = SelectField('Department', coerce=int, validators=[DataRequired()])
    program = SelectField('Program', coerce=int, validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password_reg = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def __init__(self, *args, **kwargs):
        super(RegistrationForm, self).__init__(*args, **kwargs)
        self.department.choices = [(d.id, d.name) for d in Department.query.all()]
        self.program.choices = [(p.id, p.name) for p in Program.query.all()]

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already exists.')

    def validate_matricule(self, matricule):
        user = User.query.filter_by(matricule=matricule.data).first()
        if user:
            raise ValidationError('Matricule already exists. Please use a different one.')

class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=150)])
    matricule = StringField('Matricule', validators=[Length(min=2, max=50)])
    phone = StringField('Phone Number', validators=[DataRequired(), Length(min=7, max=20)])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired(), Length(min=5, max=300)])
    parent_contact = StringField('Parent Contact', validators=[DataRequired(), Length(min=7, max=100)])
    password = PasswordField('New Password (leave blank to keep current)', validators=[Length(min=6)])
    resit_registration = BooleanField('Resit Registration')
    unvalidated_courses = StringField('Unvalidated Courses', validators=[Length(max=500)])
    internship_placement = StringField('Internship Placement', validators=[Length(max=200)])
    submit = SubmitField('Update')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class AddStudentForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    matricule = StringField('Matricule', validators=[DataRequired(), Length(min=2, max=50)])
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=150)])
    department = SelectField('Department', coerce=int, validators=[DataRequired()])
    program = SelectField('Program', coerce=int, validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Add Student')

    def __init__(self, *args, **kwargs):
        super(AddStudentForm, self).__init__(*args, **kwargs)
        self.department.choices = [(d.id, d.name) for d in Department.query.all()]
        self.program.choices = [(p.id, p.name) for p in Program.query.all()]

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already exists.')

    def validate_matricule(self, matricule):
        user = User.query.filter_by(matricule=matricule.data).first()
        if user:
            raise ValidationError('Matricule already exists. Please use a different one.')

class ResultForm(FlaskForm):
    subject = StringField('Subject', validators=[DataRequired()])
    ca_score = FloatField('CA Score', validators=[DataRequired()])
    exam_score = FloatField('Exam Score', validators=[DataRequired()])
    is_released = BooleanField('Release Results')
    submit = SubmitField('Add Result')

class FinanceForm(FlaskForm):
    fees = FloatField('Fees', validators=[DataRequired()])
    balance = FloatField('Balance', validators=[DataRequired()])
    platform_charges = FloatField('Platform Charges', validators=[DataRequired()])
    is_visible = BooleanField('Make Visible')
    submit = SubmitField('Update Finance')
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'student' or 'admin'
    name = db.Column(db.String(150), nullable=True)
    matricule = db.Column(db.String(50), nullable=True, unique=True)
    phone = db.Column(db.String(20), nullable=True)
    gender = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(300), nullable=True)
    parent_contact = db.Column(db.String(100), nullable=True)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=False)
    program_id = db.Column(db.Integer, db.ForeignKey('program.id'), nullable=False)
    resit_registration = db.Column(db.Boolean, default=False)
    unvalidated_courses = db.Column(db.String(500), nullable=True)
    has_transcripts = db.Column(db.Boolean, default=False)
    internship_placement = db.Column(db.String(200), nullable=True)

    user = db.relationship('User', backref=db.backref('student', uselist=False))
    department = db.relationship('Department', backref='students')
    program = db.relationship('Program', backref='students')

class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)

class Program(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=False)

    department = db.relationship('Department', backref='programs')

class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    subject = db.Column(db.String(150), nullable=False)
    ca_score = db.Column(db.Float, nullable=True)
    exam_score = db.Column(db.Float, nullable=True)
    is_released = db.Column(db.Boolean, default=False)

    student = db.relationship('Student', backref='results')

class Finance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    fees = db.Column(db.Float, nullable=False)
    balance = db.Column(db.Float, nullable=False)
    platform_charges = db.Column(db.Float, nullable=False)
    is_visible = db.Column(db.Boolean, default=False)

    student = db.relationship('Student', backref='finances')
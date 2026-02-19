from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import IntegrityError, OperationalError
from models import db, User, Student, Department, Program, Result, Finance
from forms import LoginForm, RegistrationForm, EditProfileForm, ForgotPasswordForm, ResetPasswordForm, AddStudentForm, ResultForm, FinanceForm
from config import Config
import os

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()
        confirm_password = form.confirm_password.data.strip()
        
        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('login.html', form=form)
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard_choice'))
        flash('Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/dashboard_choice')
@login_required
def dashboard_choice():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        return render_template('dashboard_choice.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, role='student')
        user.set_password(form.password.data)
        user.name = form.name.data
        user.matricule = form.matricule.data
        user.phone = form.phone.data
        user.gender = form.gender.data
        user.address = form.address.data
        user.parent_contact = form.parent_contact.data
        try:
            db.session.add(user)
            db.session.commit()
            student = Student(user_id=user.id, department_id=form.department.data, program_id=form.program.data)
            db.session.add(student)
            db.session.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except IntegrityError as e:
            db.session.rollback()
            flash(f'Integrity error: {str(e)}')
        except OperationalError as e:
            db.session.rollback()
            flash(f'Operational error: {str(e)}')
    return render_template('register.html', form=form)

@app.route('/debug')
def debug():
    users = User.query.all()
    output = '<h1>Users</h1><ul>'
    for u in users:
        output += f'<li>{u.username} - {u.role} - {u.name} - {u.matricule}</li>'
    output += '</ul>'
    students = Student.query.all()
    output += '<h1>Students</h1><ul>'
    for s in students:
        output += f'<li>{s.user.name} - {s.user.matricule} - User: {s.user.username if s.user else None}</li>'
    output += '</ul>'
    return output

@app.route('/student_dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect(url_for('admin_dashboard'))
    student = current_user.student
    if not student:
        flash('Student profile not found. Please contact administration.')
        return redirect(url_for('logout'))
    results = Result.query.filter_by(student_id=student.id, is_released=True).all()
    finances = Finance.query.filter_by(student_id=student.id, is_visible=True).all()
    return render_template('student_dashboard.html', student=student, results=results, finances=finances)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))
    try:
        search_query = request.args.get('search', '').strip()
        if search_query:
            students = Student.query.join(User).filter(User.matricule.ilike(f'%{search_query}%')).all()
        else:
            students = Student.query.all()
        return render_template('admin_dashboard.html', students=students, search_query=search_query)
    except Exception as e:
        return f"Operational error: {str(e)}"

@app.route('/departments')
def departments():
    deps = Department.query.all()
    return render_template('departments.html', departments=deps)

@app.route('/api/programs/<int:department_id>')
def get_programs(department_id):
    programs = Program.query.filter_by(department_id=department_id).all()
    return jsonify([{'id': p.id, 'name': p.name} for p in programs])

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.name = form.name.data
        current_user.matricule = form.matricule.data
        current_user.phone = form.phone.data
        current_user.gender = form.gender.data
        current_user.address = form.address.data
        current_user.parent_contact = form.parent_contact.data
        if current_user.role == 'student' and current_user.student:
            current_user.student.resit_registration = form.resit_registration.data
            current_user.student.unvalidated_courses = form.unvalidated_courses.data
            current_user.student.internship_placement = form.internship_placement.data
        if form.password.data:
            current_user.set_password(form.password.data)
        try:
            db.session.commit()
            flash('Profile updated successfully!')
            return redirect(url_for('student_dashboard' if current_user.role == 'student' else 'admin_dashboard'))
        except IntegrityError as e:
            db.session.rollback()
            flash(f'Integrity error: {str(e)}')
        except OperationalError as e:
            db.session.rollback()
            flash(f'Operational error: {str(e)}')
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.name.data = current_user.name
        form.matricule.data = current_user.matricule
        form.phone.data = current_user.phone if current_user.phone else ''
        form.gender.data = current_user.gender if current_user.gender else ''
        form.address.data = current_user.address if current_user.address else ''
        form.parent_contact.data = current_user.parent_contact if current_user.parent_contact else ''
        if current_user.role == 'student' and current_user.student:
            form.resit_registration.data = current_user.student.resit_registration
            form.unvalidated_courses.data = current_user.student.unvalidated_courses if current_user.student.unvalidated_courses else ''
            form.internship_placement.data = current_user.student.internship_placement if current_user.student.internship_placement else ''
    return render_template('edit_profile.html', form=form)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            # Send reset email (placeholder)
            flash('Reset link sent to your email.')
        else:
            flash('Email not found.')
    return render_template('forgot_password.html', form=form)

@app.route('/add_student', methods=['GET', 'POST'])
@login_required
def add_student():
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))
    form = AddStudentForm()
    if form.validate_on_submit():
        # Check if user with this email already exists
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('A user with this email already exists.')
            return render_template('add_student.html', form=form)
        
        # Check if student with this matricule already exists
        existing_matricule = User.query.filter_by(matricule=form.matricule.data).first()
        if existing_matricule:
            flash(f'A student with matricule {form.matricule.data} already exists.')
            return render_template('add_student.html', form=form)
        
        user = User(username=form.username.data, email=form.email.data, role='student')
        user.set_password(form.password.data)
        user.name = form.name.data
        user.matricule = form.matricule.data
        try:
            db.session.add(user)
            db.session.commit()
            student = Student(user_id=user.id, department_id=form.department.data, program_id=form.program.data)
            db.session.add(student)
            db.session.commit()
            flash('Student added successfully!')
            return redirect(url_for('admin_dashboard'))
        except IntegrityError as e:
            db.session.rollback()
            flash(f'Error adding student: This matricule or email may already exist.')
        except OperationalError as e:
            db.session.rollback()
            flash(f'Operational error: {str(e)}')
    return render_template('add_student.html', form=form)

@app.route('/delete_student/<int:student_id>')
@login_required
def delete_student(student_id):
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))
    student = Student.query.get_or_404(student_id)
    db.session.delete(student)
    db.session.delete(student.user)
    db.session.commit()
    flash('Student deleted successfully!')
    return redirect(url_for('admin_dashboard'))

@app.route('/release_results/<int:student_id>', methods=['GET', 'POST'])
@login_required
def release_results(student_id):
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))
    results = Result.query.filter_by(student_id=student_id).all()
    for result in results:
        result.is_released = True
    db.session.commit()
    flash('Results released!')
    return redirect(url_for('admin_dashboard'))

@app.route('/make_finance_visible/<int:student_id>')
@login_required
def make_finance_visible(student_id):
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))
    finances = Finance.query.filter_by(student_id=student_id).all()
    for finance in finances:
        finance.is_visible = True
    db.session.commit()
    flash('Finance details made visible!')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()
        
        # Add departments and programs
        departments_data = {
            'School of Engineering': [
                'Bachelor in Network Engineering',
                'Bachelor in Software Engineering',
                'Bachelor in Telecommunications Engineering',
                'Bachelor in Electrical Engineering',
                'Bachelor in Mechanical Engineering',
                'Bachelor in Technology Network Engineering',
                'Bachelor in Technology Software Engineering',
                'Bachelor in Technology Telecommunications Engineering',
                'Bachelor in Technology Mechanical Engineering',
                'Bachelor in Technology Electrical Engineering',
                'Masters in Network Engineering',
                'Masters in Software Engineering',
                'Masters in Telecommunications Engineering',
                'Masters in Electrical Engineering',
                'Masters in Mechanical Engineering',
                'PhD in Network Engineering',
                'PhD in Software Engineering',
                'PhD in Telecommunications Engineering',
                'PhD in Electrical Engineering',
                'PhD in Mechanical Engineering',
            ],
            'School of Agriculture': [
                'HND in Agriculture',
                'Bachelor in Agriculture',
                'Bachelor in Technology Agriculture',
                'Masters in Agriculture',
                'PhD in Agriculture',
            ],
            'School of Management Science': [
                'Bachelor in Business Management',
                'Bachelor in Technology Business Management',
                'Masters in Business Management',
                'PhD in Business Management',
            ],
            'School of Nursing': [
                'HND in Nursing',
                'HND in Midwifery',
                'Bachelors in Science Nursing',
                'Bachelors in Science Midwifery',
                'Masters in Nursing',
                'Masters in Midwifery',
                'PhD in Nursing',
                'PhD in Midwifery',
            ],
            'School of Education': [
                'Bachelors in Mathematics',
                'Bachelors in Computer Science',
                'Bachelors in History',
                'Bachelors in Philosophy',
                'Masters in Mathematics',
                'Masters in Computer Science',
                'Masters in History',
                'Masters in Philosophy',
                'PhD in Mathematics',
                'PhD in Computer Science',
                'PhD in History',
                'PhD in Philosophy',
            ],
        }
        
        for dept_name, programs in departments_data.items():
            dept = Department(name=dept_name)
            db.session.add(dept)
            db.session.flush()
            
            for prog_name in programs:
                prog = Program(name=prog_name, department_id=dept.id)
                db.session.add(prog)
        
        db.session.commit()
        
        # Add admin user
        admin = User(username='admin', email='admin@example.com', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        
    app.run(debug=True)
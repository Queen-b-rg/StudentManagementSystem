from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import IntegrityError, OperationalError
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from models import db, User, Student, Department, Program, Result, Finance, StaffAssignment, Assignment, Submission
from forms import LoginForm, RegistrationForm, EditProfileForm, ForgotPasswordForm, ResetPasswordForm, AddStudentForm, ResultForm, FinanceForm, AddStaffForm, AssignmentForm
from config import Config
import os
import socket

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def get_local_ip():
    """Return the machine's LAN IP address (best-effort)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't need to be reachable - used to determine default route
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

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
    elif current_user.role == 'staff':
        return redirect(url_for('staff_dashboard'))
    else:
        return redirect(url_for('student_dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, role=form.role.data)
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
            if form.role.data == 'student':
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
    if current_user.role not in ['admin', 'staff']:
        return redirect(url_for('student_dashboard'))
    try:
        search_query = request.args.get('search', '').strip()
        if search_query:
            users = User.query.filter(User.id != current_user.id).filter(
                (User.name.ilike(f'%{search_query}%')) | 
                (User.matricule.ilike(f'%{search_query}%')) |
                (User.username.ilike(f'%{search_query}%'))
            ).all()
        else:
            users = User.query.filter(User.id != current_user.id).all()
        return render_template('admin_dashboard.html', users=users, search_query=search_query)
    except Exception as e:
        return f"Operational error: {str(e)}"


@app.route('/staff_dashboard')
@login_required
def staff_dashboard():
    if current_user.role != 'staff':
        # allow admins to view staff dashboard if they want
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('student_dashboard'))

    # For now show basic info and quick links; can be expanded later
    try:
        # staff should see their assigned students/assignments in future
        return render_template('staff_dashboard.html', user=current_user)
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
            # timed token via itsdangerous
            token = serializer.dumps(user.email, salt='password-reset-salt')
            # build path and then replace hostname with local IP so link works from phone
            path = url_for('reset_password', token=token, _external=False)
            host_header = request.host or ''
            # determine port from host header or default to 5000
            if ':' in host_header:
                port = host_header.split(':')[1]
            else:
                port = app.config.get('PORT', 5000)
            local_ip = get_local_ip()
            reset_url = f'http://{local_ip}:{port}{path}'

            if app.config.get('MAIL_USERNAME') and app.config.get('MAIL_PASSWORD'):
                msg = Message('Password Reset Request', sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[user.email])
                msg.body = f'Click the link to reset your password:\n{reset_url}\n\nThis link will expire in 1 hour.'
                try:
                    mail.send(msg)
                    flash('Check your email for the reset link. If you do not receive it, check spam.')
                except Exception as e:
                    flash(f'Error sending email: {str(e)}')
                    # also print debug info to console
                    print('Error sending password reset email:', str(e))
                    print('Prepared reset link:', reset_url)
            else:
                # helpful local testing fallback
                flash('Email credentials not configured. Copy the reset link from the server console.')
                print('\n*** PASSWORD RESET LINK (TESTING) ***')
                print(reset_url)
                print('*** END LINK ***\n')
        else:
            flash('If an account with that email exists, a reset link has been sent to your email.')
    return render_template('forgot_password.html', form=form)

@app.route('/test_email/<email>')
def test_email(email):
    print(f'\n--- Test Email Route ---')
    print(f'MAIL_SERVER: {app.config.get("MAIL_SERVER")}')
    print(f'MAIL_PORT: {app.config.get("MAIL_PORT")}')
    print(f'MAIL_USE_TLS: {app.config.get("MAIL_USE_TLS")}')
    print(f'MAIL_USERNAME: {app.config.get("MAIL_USERNAME")}')
    print(f'MAIL_PASSWORD: {"***" if app.config.get("MAIL_PASSWORD") else "NOT SET"}')
    print(f'MAIL_DEFAULT_SENDER: {app.config.get("MAIL_DEFAULT_SENDER")}')
    print(f'------------------------\n')
    
    if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
        return {'status': 'ERROR', 'message': f'Email credentials not configured!', 'MAIL_USERNAME': app.config['MAIL_USERNAME'], 'MAIL_PASSWORD': 'NOT SET'}
    
    try:
        msg = Message('Test Email from StudentApp', sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[email])
        msg.body = 'This is a test email from StudentApp to verify your email configuration is working.'
        mail.send(msg)
        print(f'✓ Test email sent successfully to {email}')
        return {'status': 'SUCCESS', 'message': f'Test email sent to {email}'}
    except Exception as e:
        error_msg = str(e)
        print(f'✗ Error sending test email: {error_msg}')
        return {'status': 'ERROR', 'message': f'Error: {error_msg}'}

@app.route('/mail_config')
def mail_config():
    """Display current mail configuration for debugging"""
    return {
        'MAIL_SERVER': app.config.get('MAIL_SERVER'),
        'MAIL_PORT': app.config.get('MAIL_PORT'),
        'MAIL_USE_TLS': app.config.get('MAIL_USE_TLS'),
        'MAIL_USERNAME': app.config.get('MAIL_USERNAME'),
        'MAIL_PASSWORD': '***SET***' if app.config.get('MAIL_PASSWORD') else 'NOT SET',
        'MAIL_DEFAULT_SENDER': app.config.get('MAIL_DEFAULT_SENDER'),
        'Instructions': 'Set MAIL_USERNAME and MAIL_PASSWORD environment variables before starting the app'
    }

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)  # 1 hour expiry
    except SignatureExpired:
        flash('The reset link has expired. Please request a new one.')
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash('Invalid reset link.')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.')
        return redirect(url_for('login'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        print(f'\n--- Password Reset Successful ---')
        print(f'User: {user.email}')
        print(f'Password has been updated in database')
        print(f'--------------------------------\n')
        flash('Password reset successful. Please login with your new password.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

@app.route('/add_student', methods=['GET', 'POST'])
@login_required
def add_student():
    if current_user.role not in ['admin', 'staff']:
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

@app.route('/add_staff', methods=['GET', 'POST'])
@login_required
def add_staff():
    if current_user.role not in ['admin', 'staff']:
        return redirect(url_for('student_dashboard'))
    form = AddStaffForm()
    if form.validate_on_submit():
        # Check if user with this email already exists
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('A user with this email already exists.')
            return render_template('add_staff.html', form=form)
        
        user = User(username=form.username.data, email=form.email.data, role='staff')
        user.set_password(form.password.data)
        user.name = form.name.data
        user.matricule = form.matricule.data if form.matricule.data else None
        try:
            db.session.add(user)
            db.session.commit()
            flash('Staff added successfully!')
            return redirect(url_for('admin_dashboard'))
        except IntegrityError as e:
            db.session.rollback()
            flash(f'Error adding staff: This email may already exist.')
        except OperationalError as e:
            db.session.rollback()
            flash(f'Operational error: {str(e)}')
    return render_template('add_staff.html', form=form)

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role not in ['admin', 'staff']:
        return redirect(url_for('student_dashboard'))
    user = User.query.get_or_404(user_id)
    if user.role == 'student' and user.student:
        db.session.delete(user.student)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!')
    return redirect(url_for('admin_dashboard'))

@app.route('/manage_staff/<int:user_id>')
@login_required
def manage_staff(user_id):
    if current_user.role not in ['admin', 'staff']:
        return redirect(url_for('student_dashboard'))
    user = User.query.get_or_404(user_id)
    if user.role != 'staff':
        flash('User is not a staff member.')
        return redirect(url_for('admin_dashboard'))
    return render_template('manage_staff.html', user=user)

@app.route('/assign_courses/<int:user_id>')
@login_required
def assign_courses(user_id):
    if current_user.role not in ['admin', 'staff']:
        return redirect(url_for('student_dashboard'))
    user = User.query.get_or_404(user_id)
    # Render a simple page for assigning courses (UI to be expanded)
    programs = Program.query.all()
    return render_template('assign_courses.html', staff=user, programs=programs)

@app.route('/manage_grades/<int:user_id>')
@login_required
def manage_grades(user_id):
    if current_user.role not in ['admin', 'staff']:
        return redirect(url_for('student_dashboard'))
    user = User.query.get_or_404(user_id)
    # Show assigned students and their results for grading
    assignments = StaffAssignment.query.filter_by(staff_id=user.id).all()
    students = [sa.student for sa in assignments]
    return render_template('manage_grades.html', staff=user, students=students)

@app.route('/view_assigned_students/<int:user_id>')
@login_required
def view_assigned_students(user_id):
    if current_user.role not in ['admin', 'staff']:
        return redirect(url_for('student_dashboard'))
    user = User.query.get_or_404(user_id)
    # list students assigned to this staff
    assignments = StaffAssignment.query.filter_by(staff_id=user.id).all()
    students = [sa.student for sa in assignments]
    return render_template('view_assigned_students.html', staff=user, students=students)

@app.route('/reset_staff_password/<int:user_id>')
@login_required
def reset_staff_password(user_id):
    if current_user.role not in ['admin', 'staff']:
        return redirect(url_for('student_dashboard'))
    user = User.query.get_or_404(user_id)
    # Generate new password or something
    new_password = 'temp123'
    user.set_password(new_password)
    db.session.commit()
    flash(f'Password reset to: {new_password}')
    return redirect(url_for('manage_staff', user_id=user_id))

@app.route('/edit_permissions/<int:user_id>')
@login_required
def edit_permissions(user_id):
    if current_user.role not in ['admin', 'staff']:
        return redirect(url_for('student_dashboard'))
    user = User.query.get_or_404(user_id)
    # Minimal permissions editor
    return render_template('edit_permissions.html', staff=user)

@app.route('/view_attendance_log/<int:user_id>')
@login_required
def view_attendance_log(user_id):
    if current_user.role not in ['admin', 'staff']:
        return redirect(url_for('student_dashboard'))
    user = User.query.get_or_404(user_id)
    # Minimal attendance view
    attendance = []
    return render_template('attendance_log.html', staff=user, attendance=attendance)

@app.route('/generate_report/<int:user_id>')
@login_required
def generate_report(user_id):
    if current_user.role not in ['admin', 'staff']:
        return redirect(url_for('student_dashboard'))
    user = User.query.get_or_404(user_id)
    # Simple report page (expand with real data later)
    return render_template('generate_report.html', staff=user)

@app.route('/add_assignments/<int:user_id>', methods=['GET', 'POST'])
@login_required
def add_assignments(user_id):
    if current_user.role not in ['admin', 'staff']:
        return redirect(url_for('student_dashboard'))
    user = User.query.get_or_404(user_id)
    form = AssignmentForm()
    if form.validate_on_submit():
        assignment = Assignment(title=form.title.data, description=form.description.data, staff_id=user.id, due_date=form.due_date.data)
        db.session.add(assignment)
        db.session.commit()
        flash('Assignment created successfully.')
        return redirect(url_for('manage_staff', user_id=user_id))
    return render_template('add_assignment.html', form=form, staff=user)

@app.route('/view_submitted_assignments/<int:user_id>')
@login_required
def view_submitted_assignments(user_id):
    if current_user.role not in ['admin', 'staff']:
        return redirect(url_for('student_dashboard'))
    user = User.query.get_or_404(user_id)
    # gather submissions for assignments created by this staff
    assignments = Assignment.query.filter_by(staff_id=user.id).all()
    submissions = []
    for a in assignments:
        for s in a.submissions:
            submissions.append({'assignment': a, 'submission': s})
    return render_template('view_submissions.html', staff=user, submissions=submissions)

@app.route('/add_notes/<int:user_id>')
@login_required
def add_notes(user_id):
    if current_user.role not in ['admin', 'staff']:
        return redirect(url_for('student_dashboard'))
    user = User.query.get_or_404(user_id)
    # Minimal add-notes page
    return render_template('add_notes.html', staff=user)

@app.route('/release_results/<int:student_id>', methods=['GET', 'POST'])
@login_required
def release_results(student_id):
    if current_user.role not in ['admin', 'staff']:
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
    if current_user.role not in ['admin', 'staff']:
        return redirect(url_for('student_dashboard'))
    finances = Finance.query.filter_by(student_id=student_id).all()
    for finance in finances:
        finance.is_visible = True
    db.session.commit()
    flash('Finance details made visible!')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    with app.app_context():
        # Only create tables if they do not exist. Do NOT drop the database on startup.
        db.create_all()

        # Seed departments and programs if none exist
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

        if Department.query.first() is None:
            for dept_name, programs in departments_data.items():
                dept = Department(name=dept_name)
                db.session.add(dept)
                db.session.flush()

                for prog_name in programs:
                    prog = Program(name=prog_name, department_id=dept.id)
                    db.session.add(prog)
            db.session.commit()

        # Add admin user if not present
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@example.com', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()

    app.run(host='0.0.0.0', debug=True)
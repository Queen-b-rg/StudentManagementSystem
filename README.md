# Student Management System

A Flask-based student management system with authentication, student and admin dashboards.

## Features

- User registration and login
- Student dashboard: view program, results, finances
- Admin dashboard: manage students, release results, manage finances
- Departments page
- Edit profile and forgot password

## Setup

1. Install dependencies: `pip install -r requirements.txt`
2. Run the app: `python app.py`
3. Open http://localhost:5000

## Deployment on Render

1. Push to GitHub
2. Connect to Render
3. Set environment variables: SECRET_KEY, DATABASE_URL (for PostgreSQL), MAIL_USERNAME, MAIL_PASSWORD
4. Deploy

## Scalability

- Uses SQLAlchemy ORM
- Can switch to PostgreSQL for production
- Modular code structure for easy extension
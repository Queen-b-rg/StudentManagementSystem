import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key'
    # SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI') or "sqlite:///app.db"
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgresql_flask_user:nqbhiUocLRJdjMDCKUSk9M0ce3JrcGux@dpg-d6e2bch5pdvs73fnpam0-a.frankfurt-postgres.render.com/postgresql_flask'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'betisier8@gmail.com'
    MAIL_PASSWORD = 'hdbccaypbwinwrhj'
    MAIL_DEFAULT_SENDER = 'betisier8@gmail.com'
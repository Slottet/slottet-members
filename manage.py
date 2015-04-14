# -*- coding: utf-8 -*-
# manage.py
from flask.ext.script import Manager, prompt_bool
from flask.ext.migrate import Migrate, MigrateCommand
from app import app, db, Role, date, datetime, timedelta, User

migrate = Migrate(app, db)

manager = Manager(app)
manager.add_command('db', MigrateCommand)

# Only for errors
@manager.command
def manual_send():
    users = User.query.all()
    for user in users:
        print user.send_email()

@manager.command
def send_email():
    weekday = date.today().weekday()
    if weekday == 0:
        users = User.query.all()
        for user in users:
            print user.send_email()

@manager.command
def add_roles():
    admin_role = Role("ADMIN", "Administratör")
    user_role = Role("USER", "Användare")
    db.session.add_all([user_role, admin_role])
    db.session.commit()

@manager.command
def db_drop():
    "Drops database tables"
    if prompt_bool("Are you sure you want to lose all your data"):
        #db.reflect()
        db.drop_all()

@manager.command
def db_create():
    "Creates database tables from sqlalchemy models"
    #db.reflect()
    db.create_all()

@manager.command
def db_recreate(default_data=True, sample_data=False):
    "Recreates database tables (same as issuing 'drop' and then 'create')"
    db_drop()
    db_create()

    admin_role = Role("ADMIN", "Administratör")
    user_role = Role("USER", "Användare")
    db.session.add_all([user_role, admin_role])
    db.session.commit()

if __name__ == "__main__":
    manager.run()
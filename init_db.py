from app import db, User, Notification

# Drop all tables (only do this if you want to reset the database)
db.drop_all()
db.drop_all(bind='notifications')

# Create all tables
db.create_all()
db.create_all(bind='notifications')

print("Database initialized successfully.")

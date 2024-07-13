from app import db, User, bcrypt

db.create_all()

# Function to create a new user
def create_user(username, password, is_admin=False):
    # Check if user already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        print(f"User '{username}' already exists.")
        return

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password, is_admin=is_admin)
    db.session.add(new_user)
    db.session.commit()
    print(f"User '{username}' created successfully.")

# Get user inputs
admin_username = input("Enter admin username: ")
admin_password = input("Enter admin password: ")

user_username = input("Enter regular user username: ")
user_password = input("Enter regular user password: ")

# Create users
create_user(admin_username, admin_password, is_admin=True)
create_user(user_username, user_password, is_admin=False)

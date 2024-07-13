import json
import boto3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from functools import wraps
from flask import Blueprint

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/users.db'
app.config['SQLALCHEMY_BINDS'] = {'notifications': 'sqlite:///instance/notifications.db'}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)

with open('r2_credentials.json') as f:
    r2_credentials = json.load(f)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Notification(db.Model):
    __bind_key__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    folder = db.Column(db.String(255), nullable=False)
    text = db.Column(db.Text, nullable=False)

db.create_all()
db.create_all(bind='notifications')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            return "You are not authorized to view this page.", 403
        return f(*args, **kwargs)
    return decorated_function

@app.template_filter()
def filesizeformat(value):
    """Format the file size."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if value < 1024.0:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} PB"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your username and/or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('is_admin', None)
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    admin = session.get('is_admin')
    s3 = boto3.client('s3',
                      endpoint_url=r2_credentials['endpoint_url'],
                      aws_access_key_id=r2_credentials['aws_access_key_id'],
                      aws_secret_access_key=r2_credentials['aws_secret_access_key'])

    if request.method == 'POST':
        prefix = request.form.get('prefix', '')
        objects = s3.list_objects_v2(Bucket=r2_credentials['bucket_name'], Prefix=prefix, Delimiter='/')
    else:
        objects = s3.list_objects_v2(Bucket=r2_credentials['bucket_name'], Delimiter='/')

    folders = [content['Prefix'] for content in objects.get('CommonPrefixes', [])]

    return render_template('index.html', folders=folders, admin=admin)

@app.route('/folder/<path:prefix>/', methods=['GET', 'POST'])
@login_required
def folder(prefix):
    admin = session.get('is_admin')
    s3 = boto3.client('s3',
                      endpoint_url=r2_credentials['endpoint_url'],
                      aws_access_key_id=r2_credentials['aws_access_key_id'],
                      aws_secret_access_key=r2_credentials['aws_secret_access_key'])
    
    if request.method == 'POST':
        if 'save' in request.form:
            notification_text = request.form['notification']
            notification = Notification.query.filter_by(folder=prefix).first()
            if notification:
                notification.text = notification_text
            else:
                notification = Notification(folder=prefix, text=notification_text)
                db.session.add(notification)
            db.session.commit()
        elif 'delete' in request.form:
            notification = Notification.query.filter_by(folder=prefix).first()
            if notification:
                db.session.delete(notification)
                db.session.commit()
        return redirect(url_for('folder', prefix=prefix))

    notification = Notification.query.filter_by(folder=prefix).first()
    notification_text = notification.text if notification else 'None'

    max_keys = 10  # number of files to display per page
    current_page = int(request.args.get('page', 1))
    continuation_token = request.args.get('continuation_token')
    list_params = {'Bucket': r2_credentials['bucket_name'], 'Prefix': prefix, 'MaxKeys': max_keys}
    if continuation_token:
        list_params['ContinuationToken'] = continuation_token

    response = s3.list_objects_v2(**list_params)

    files = response.get('Contents', [])
    next_token = response.get('NextContinuationToken')

    # Generate custom URLs
    for file in files:
        file['presigned_url'] = f"https://shillongteerresults.net/{file['Key']}"

    # Pagination logic
    total_files = response['KeyCount']
    total_pages = (total_files // max_keys) + (1 if total_files % max_keys > 0 else 0)
    previous_token = None
    if current_page > 1:
        previous_token = continuation_token
        # Fetch previous continuation tokens
        for _ in range(current_page - 1):
            prev_response = s3.list_objects_v2(Bucket=r2_credentials['bucket_name'], Prefix=prefix, MaxKeys=max_keys, ContinuationToken=previous_token)
            previous_token = prev_response.get('NextContinuationToken')

    return render_template('folder.html', files=files, folder_name=prefix, notification=notification_text, admin=admin, next_token=next_token, previous_token=previous_token, total_pages=total_pages, current_page=current_page)

@app.route('/search', methods=['GET'])
@login_required
def search():
    query = request.args.get('query', '')
    if query:
        s3 = boto3.client('s3',
                          endpoint_url=r2_credentials['endpoint_url'],
                          aws_access_key_id=r2_credentials['aws_access_key_id'],
                          aws_secret_access_key=r2_credentials['aws_secret_access_key'])
        
        list_params = {'Bucket': r2_credentials['bucket_name'], 'Prefix': query}
        response = s3.list_objects_v2(**list_params)
        files = response.get('Contents', [])

        # Generate custom URLs
        for file in files:
            file['presigned_url'] = f"https://shillongteerresults.net/{file['Key']}"
    else:
        files = []

    return render_template('search.html', files=files)

@app.route('/public/folder/<path:prefix>/', methods=['GET'])
def public_folder(prefix):
    s3 = boto3.client('s3',
                      endpoint_url=r2_credentials['endpoint_url'],
                      aws_access_key_id=r2_credentials['aws_access_key_id'],
                      aws_secret_access_key=r2_credentials['aws_secret_access_key'])
    
    notification = Notification.query.filter_by(folder=prefix).first()
    notification_text = notification.text if notification else 'None'

    max_keys = 10  # number of files to display per page
    current_page = int(request.args.get('page', 1))
    continuation_token = request.args.get('continuation_token')
    list_params = {'Bucket': r2_credentials['bucket_name'], 'Prefix': prefix, 'MaxKeys': max_keys}
    if continuation_token:
        list_params['ContinuationToken'] = continuation_token

    response = s3.list_objects_v2(**list_params)

    files = response.get('Contents', [])
    next_token = response.get('NextContinuationToken')

    # Generate custom URLs
    for file in files:
        file['presigned_url'] = f"https://shillongteerresults.net/{file['Key']}"

    # Pagination logic
    total_files = response['KeyCount']
    total_pages = (total_files // max_keys) + (1 if total_files % max_keys > 0 else 0)
    previous_token = None
    if current_page > 1:
        previous_token = continuation_token
        # Fetch previous continuation tokens
        for _ in range(current_page - 1):
            prev_response = s3.list_objects_v2(Bucket=r2_credentials['bucket_name'], Prefix=prefix, MaxKeys=max_keys, ContinuationToken=previous_token)
            previous_token = prev_response.get('NextContinuationToken')

    return render_template('public_folder.html', files=files, folder_name=prefix, notification=notification_text, next_token=next_token, previous_token=previous_token, total_pages=total_pages, current_page=current_page)

if __name__ == '__main__':
    app.run(debug=True)

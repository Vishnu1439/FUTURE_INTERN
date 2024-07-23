from flask import Flask, render_template, redirect, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
import pyotp
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'KMBU3SQGOIAPK7TUZWIKLU2ZIDNBQL6R'  # Use your generated secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False, default=pyotp.random_base32())

    def check_password(self, password):
        return check_password_hash(self.password, password)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
@login_required
def index():
    return 'Welcome to the protected area'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            print(f"Entered Password: {password}")  # Debug print statement
            print(f"Stored Hashed Password: {user.password}")  # Debug print statement
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('two_factor'))
        else:
            flash('Invalid username or password.')
    return render_template('login.html')

@app.route('/two-factor', methods=['GET', 'POST'])
@login_required
def two_factor():
    print('1')
    if request.method == 'POST':
        print('2')
        token = request.form['token']
        if pyotp.TOTP(current_user.otp_secret).verify(token):
            print('3')
            flash('Logged in successfully.')
            return redirect(url_for('index'))
        else:
            print('4')
            flash('Invalid token.')
            return redirect(url_for('logout'))
    return render_template('two_factor.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/create_user')
def create_user():
    username = 'testuser'
    if User.query.filter_by(username=username).first():
        return f'User with username {username} already exists.'

    otp_secret = pyotp.random_base32()
    hashed_password = generate_password_hash('testpassword', method='pbkdf2:sha256')
    print(f"Hashed Password: {hashed_password}")  # Debug print statement
    new_user = User(username=username, password=hashed_password, otp_secret=otp_secret)
    db.session.add(new_user)
    db.session.commit()
    return f'User created successfully with OTP secret: {otp_secret}'

@app.route('/delete_user')
def delete_user():
    username = 'testuser'
    user = User.query.filter_by(username=username).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        return f'User {username} deleted successfully.'
    return f'User {username} does not exist.'

@app.route('/status')
def status():
    if current_user.is_authenticated:
        return f'Logged in as: {current_user.username}'
    else:
        return 'Not logged in'

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

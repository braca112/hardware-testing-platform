import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, get_flashed_messages
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_apscheduler import APScheduler
from flask_migrate import Migrate

app = Flask(__name__)
# Uzmi DATABASE_URL iz okruženja
database_url = os.getenv('DATABASE_URL', 'sqlite:///hardware.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
if 'postgresql://' in database_url and 'sslmode' not in database_url:
    database_url = database_url + '?sslmode=require'
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Konfiguracija za APScheduler (privremeno onemogućena)
# scheduler = APScheduler()
# scheduler.init_app(app)
# scheduler.start()

# Provera da li su tabele kreirane
tables_created = False
with app.app_context():
    try:
        db.drop_all()  # Obriši sve postojeće tabele (za svaki slučaj)
        db.create_all()
        app.logger.info("Database tables created successfully!")
        tables_created = True
    except Exception as e:
        app.logger.error(f"Error creating database tables: {str(e)}")
        tables_created = False

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Hardware model
class Hardware(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner = db.relationship('User', backref='hardware')

# Reservation model
class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hardware_id = db.Column(db.Integer, db.ConcurrentModificationExceptiondb.ForeignKey('hardware.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    hours = db.Column(db.Integer, nullable=False)
    start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    hardware = db.relationship('Hardware', backref='reservations')
    user = db.relationship('User', backref='reservations')

@login_manager.user_loader
def load_user(user_id):
    if not tables_created:
        return None
    return db.session.get(User, int(user_id))

@app.route('/')
def home():
    if not tables_created:
        return "Database tables could not be created. Please check the logs for more information.", 500
    hardware_list = Hardware.query.all()
    now = datetime.utcnow()
    for hardware in hardware_list:
        active_reservations = Reservation.query.filter_by(hardware_id=hardware.id).filter(Reservation.end_time > now).all()
        hardware.is_available = len(active_reservations) == 0
    return render_template('index.html', hardware=hardware_list)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if not tables_created:
        return "Database tables could not be created. Please check the logs for more information.", 500
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'danger')
            return redirect(url_for('register'))
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if not tables_created:
        return "Database tables could not be created. Please check the logs for more information.", 500
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            get_flashed_messages()  # Čistimo poruke pre redirekcije
            return redirect(url_for('home'))
        flash('Invalid username or password.', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    if not tables_created:
        return "Database tables could not be created. Please check the logs for more information.", 500
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/add-hardware', methods=['GET', 'POST'])
@login_required
def add_hardware():
    if not tables_created:
        return "Database tables could not be created. Please check the logs for more information.", 500
    if request.method == 'POST':
        name = request.form['name']
        price = float(request.form['price'])
        if price <= 0:
            flash('Price must be greater than 0.', 'danger')
            return redirect(url_for('add_hardware'))
        new_hardware = Hardware(name=name, price=price, owner_id=current_user.id)
        db.session.add(new_hardware)
        db.session.commit()
        flash('Hardware added successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('add_hardware.html')

@app.route('/reserve/<int:hardware_id>', methods=['GET', 'POST'])
@login_required
def reserve(hardware_id):
    if not tables_created:
        return "Database tables could not be created. Please check the logs for more information.", 500
    hardware = Hardware.query.get_or_404(hardware_id)
    now = datetime.utcnow()
    active_reservations = Reservation.query.filter_by(hardware_id=hardware.id).filter(Reservation.end_time > now).all()
    if active_reservations:
        flash('This hardware is already reserved.', 'danger')
        return redirect(url_for('home'))
    if request.method == 'POST':
        hours = int(request.form['hours'])
        if hours < 1 or hours > 24:
            flash('Hours must be between 1 and 24.', 'danger')
            return redirect(url_for('reserve', hardware_id=hardware_id))
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(hours=hours)
        new_reservation = Reservation(
            hardware_id=hardware.id,
            user_id=current_user.id,
            hours=hours,
            start_time=start_time,
            end_time=end_time,
            created_at=start_time
        )
        db.session.add(new_reservation)
        db.session.commit()
        flash('Reservation successful!', 'success')
        return redirect(url_for('home'))
    return render_template('reserve.html', hardware=hardware)

@app.route('/reservations')
@login_required
def reservations():
    if not tables_created:
        return "Database tables could not be created. Please check the logs for more information.", 500
    reservation_list = Reservation.query.filter_by(user_id=current_user.id).all()
    return render_template('reservations.html', reservations=reservation_list)

@app.route('/cancel-reservation/<int:reservation_id>', methods=['POST'])
@login_required
def cancel_reservation(reservation_id):
    if not tables_created:
        return "Database tables could not be created. Please check the logs for more information.", 500
    reservation = Reservation.query.get_or_404(reservation_id)
    if reservation.user_id != current_user.id:
        flash('You can only cancel your own reservations.', 'danger')
        return redirect(url_for('reservations'))
    db.session.delete(reservation)
    db.session.commit()
    flash('Reservation cancelled successfully!', 'success')
    return redirect(url_for('reservations'))

@app.route('/edit-hardware/<int:hardware_id>', methods=['GET', 'POST'])
@login_required
def edit_hardware(hardware_id):
    if not tables_created:
        return "Database tables could not be created. Please check the logs for more information.", 500
    try:
        app.logger.info(f"Attempting to load hardware with ID: {hardware_id}")
        hardware = Hardware.query.get_or_404(hardware_id)
        app.logger.info(f"Loaded hardware: {hardware.id}, name: {hardware.name}, price: {hardware.price}, owner_id: {hardware.owner_id}")
        app.logger.info(f"Current user ID: {current_user.id}")
        if hardware.owner_id != current_user.id:
            flash('You can only edit your own hardware.', 'danger')
            app.logger.info("User not authorized to edit this hardware")
            return redirect(url_for('home'))
        if request.method == 'POST':
            app.logger.info("Processing POST request to update hardware")
            hardware.name = request.form['name']
            hardware.price = float(request.form['price'])
            if hardware.price <= 0:
                flash('Price must be greater than 0.', 'danger')
                app.logger.info("Invalid price, must be greater than 0")
                return redirect(url_for('edit_hardware', hardware_id=hardware.id))
            db.session.commit()
            flash('Hardware updated successfully!', 'success')
            app.logger.info("Hardware updated successfully")
            return redirect(url_for('home'))
        app.logger.info("Rendering edit_hardware.html template")
        return render_template('edit_hardware.html', hardware=hardware)
    except Exception as e:
        app.logger.error(f"Error in edit_hardware route: {str(e)}")
        flash('An error occurred while trying to edit the hardware.', 'danger')
        return redirect(url_for('home'))

@app.route('/delete-hardware/<int:hardware_id>', methods=['POST'])
@login_required
def delete_hardware(hardware_id):
    if not tables_created:
        return "Database tables could not be created. Please check the logs for more information.", 500
    try:
        hardware = Hardware.query.get_or_404(hardware_id)
        app.logger.info(f"Attempting to delete hardware with ID: {hardware_id}")
        if hardware.owner_id != current_user.id:
            flash('You can only delete your own hardware.', 'danger')
            app.logger.info("User not authorized to delete this hardware")
            return redirect(url_for('home'))
        active_reservations = Reservation.query.filter_by(hardware_id=hardware.id).filter(Reservation.end_time > datetime.utcnow()).all()
        if active_reservations:
            flash('Cannot delete hardware with active reservations.', 'danger')
            app.logger.info("Cannot delete hardware due to active reservations")
            return redirect(url_for('home'))
        db.session.delete(hardware)
        db.session.commit()
        flash('Hardware deleted successfully!', 'success')
        app.logger.info("Hardware deleted successfully")
        return redirect(url_for('home'))
    except Exception as e:
        app.logger.error(f"Error in delete_hardware route: {str(e)}")
        flash('An error occurred while trying to delete the hardware.', 'danger')
        return redirect(url_for('home'))

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
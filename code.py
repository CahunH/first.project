from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///password_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Clave secreta para el cifrado (esto debe ser generado y guardado de forma segura)
key = Fernet.generate_key()
cipher_suite = Fernet(key)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class PasswordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service = db.Column(db.String(150), nullable=False)
    service_name = db.Column(db.String(150), nullable=False)
    encrypted_password = db.Column(db.LargeBinary, nullable=False)

    def set_password(self, password):
        self.encrypted_password = cipher_suite.encrypt(password.encode())

    def get_password(self):
        return cipher_suite.decrypt(self.encrypted_password).decode()

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = data['password']
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400
    new_user = User(username=username)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']
    user = User.query.filter_by(username=username).first()
    if user is None or not user.check_password(password):
        return jsonify({'message': 'Invalid username or password'}), 401
    return jsonify({'message': 'Login successful'}), 200

@app.route('/add_password', methods=['POST'])
def add_password():
    data = request.json
    username = data['username']
    service = data['service']
    service_name = data['service_name']
    password = data['password']
    user = User.query.filter_by(username=username).first()
    if user is None:
        return jsonify({'message': 'User not found'}), 404
    new_entry = PasswordEntry(user_id=user.id, service=service, service_name=service_name)
    new_entry.set_password(password)
    db.session.add(new_entry)
    db.session.commit()
    return jsonify({'message': 'Password added successfully'}), 201

@app.route('/get_passwords', methods=['POST'])
def get_passwords():
    data = request.json
    username = data['username']
    user = User.query.filter_by(username=username).first()
    if user is None:
        return jsonify({'message': 'User not found'}), 404
    entries = PasswordEntry.query.filter_by(user_id=user.id).all()
    passwords = [
        {'service': entry.service, 'service_name': entry.service_name, 'password': entry.get_password()}
        for entry in entries
    ]
    return jsonify(passwords), 200

if __name__ == '__main__':
    app.run(debug=True)

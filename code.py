# app.py
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    # lógica de login
    pass

@app.route('/add_password', methods=['POST'])
def add_password():
    # lógica para añadir contraseña
    pass

@app.route('/get_password', methods=['GET'])
def get_password():
    # lógica para recuperar contraseña
    pass

if __name__ == '__main__':
    app.run(debug=True)

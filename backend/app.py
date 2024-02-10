import datetime 
import json
import os
from functools import wraps
import time
from flask import Flask, jsonify, request, send_from_directory, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS, cross_origin
import jwt
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from werkzeug.utils import secure_filename
from flask_cors import CORS





app = Flask(__name__)
app.secret_key = 'secret_secret_key'
CORS(app)


# SQLAlchemy configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///samp.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

app_directory = os.path.dirname(__file__)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(100), nullable=False)
    img = db.Column(db.String(100))

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    riter = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(100), nullable=False)
    lend = db.Column(db.Boolean, default=False)
    userid = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('books', lazy=True))
    image_filename = db.Column(db.String(255)) 


class Lend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref="lends")
    book_id = db.Column(db.Integer, db.ForeignKey("book.id"), nullable=False)
    book = db.relationship("Book", backref="lends")
    borrowed_at = db.Column(db.DateTime, nullable=False)

def generate_token(user_id):
    expiration = int(time.time()) + 3600
    payload = {'user_id': user_id, 'exp': expiration}
    token = jwt.encode(payload, 'secret-secret-key', algorithm='HS256')
    return token

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

        return f(current_user_id, *args, **kwargs)

    return decorated

def model_to_dict(model):
    serialized_model = {}
    for key in model.__mapper__.c.keys():
        serialized_model[key] = getattr(model, key)
    return serialized_model

CORS(app)

import datetime

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data["username"]
    password = data["password"]

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        expires = datetime.timedelta(hours=1)
        access_token = create_access_token(identity=user.id, expires_delta=expires)
        image_url = f"{request.url_root}{UPLOAD_FOLDER}/{user.img}"

        return jsonify({'access_token': access_token, 'image_url': image_url}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/addbook', methods=['POST'])
@jwt_required()
def addbook():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if current_user.role != "1":
        return jsonify({'error': 'Only managers are allowed to delete books'}), 403
    
    request_data = request.get_json()
    name = request_data['book_name']
    riter = request_data['riter']
    date = request_data['date']
    userid = get_jwt_identity()

    new_book = Book(name=name, riter=riter, date=date, userid=userid)
    db.session.add(new_book)
    db.session.commit()

    return jsonify({'message': 'Book created successfully'}), 201

@app.route('/getbooks', methods=['GET'])
def get_books():
    try:
        books = Book.query.all()
        books_list = [{'book_id': book.id, 'book_name': book.name, 'riter': book.riter, 'date': book.date, 'lend': book.lend} for book in books]

        return jsonify({'books': books_list}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/deletebook/<int:book_id>', methods=['DELETE'])
@jwt_required()
def delete_book(book_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if current_user.role != "1":
        return jsonify({'error': 'Only managers are allowed to delete books'}), 403

    userid = get_jwt_identity()
    book_to_delete = Book.query.filter_by(id=book_id, userid=userid).first()

    if not book_to_delete:
        return jsonify({'error': 'Book not found or user does not have permission to delete'}), 404

    db.session.delete(book_to_delete)
    db.session.commit()

    return jsonify({'message': 'Book deleted successfully'}), 200




@app.route('/register', methods=['POST'])
def register():

        username = request.form.get('username')
        password = request.form.get('password')
        print(password)
        role = request.form.get('role')
        print(username)

        # Get the uploaded file
        file = request.files.get('file')
        
        if file:
            print("Uploaded file:", file.filename)

        # Save the file to the server
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            print("Uploaded file saved:", filepath)

        # Check if the username is already taken
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'message': 'Username is already taken'}), 400

        # # Hash and salt the password using Bcrypt
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # # Create a new user and add to the database
        new_user = User(username=username, password=hashed_password,role=role,img=filename)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'User created successfully'}), 201

@app.route('/lendbook', methods=['POST'])
@jwt_required()
def lend_book():
    try:
        user_id = get_jwt_identity()
        book_id = request.json.get('book_id')

        user = User.query.get(user_id)
        book = Book.query.get(book_id)
        if not user or not book:
            return jsonify({'error': 'Invalid user or book'}), 404

        if book.lend:
            return jsonify({'error': 'Book is already lent'}), 409

        current_time = datetime.datetime.now()
        lend = Lend(user_id=user_id, book_id=book_id, borrowed_at=current_time)
        db.session.add(lend)

        book.lend = True
        db.session.commit()

        return jsonify({'message': 'Book lent successfully'}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/updatebook/<int:book_id>', methods=['PUT'])
@jwt_required()
def update_book(book_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if current_user.role != "1":
        return jsonify({'error': 'Only managers are allowed to delete books'}), 403
    try:
        userid = get_jwt_identity()
        book_to_update = Book.query.filter_by(id=book_id, userid=userid).first()

        if not book_to_update:
            return jsonify({'error': 'Book not found or user does not have permission to update'}), 404

        request_data = request.get_json()
        updated_name = request_data.get('name', book_to_update.name)
        updated_riter = request_data.get('riter', book_to_update.riter)
        updated_date = request_data.get('date', book_to_update.date)

        book_to_update.name = updated_name
        book_to_update.riter = updated_riter
        book_to_update.date = updated_date

        db.session.commit()

        return jsonify({'message': 'Book updated successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/returnbook/<int:lend_id>', methods=['POST'])
@jwt_required()
def return_book(lend_id):
    try:
        current_user_id = get_jwt_identity()

        lend_record = Lend.query.filter_by(id=lend_id, user_id=current_user_id).first()
        if not lend_record:
            return jsonify({'error': 'Lending record not found or user does not have permission to return'}), 404

        book = lend_record.book
        book.lend = False
        db.session.delete(lend_record)
        db.session.commit()

        return jsonify({'message': 'Book returned successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/getusers', methods=['GET'])
def get_users():
    try:
        users = User.query.all()
        users_list = [{'id': user.id, 'username': user.username, 'password': user.password, 'role': user.role} for user in users]

        return jsonify({'users': users_list}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500  

@app.route('/deleteuser/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if current_user.role != "1":
        return jsonify({'error': 'Only managers are allowed to delete books'}), 403

    user_to_delete = User.query.get(user_id)
    if not user_to_delete:
        return jsonify({'error': 'User not found'}), 404

    db.session.delete(user_to_delete)
    db.session.commit()

    return jsonify({'message': 'User deleted successfully'}), 200


@app.route('/updateuser/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    user = User.query.get(user_id)
    if user:
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        file = request.files.get('file')

        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            user.img = filename

        user.username = username
        user.role = role
        if password:
            user.password = bcrypt.generate_password_hash(password).decode('utf-8')

        db.session.commit()
        return jsonify({'message': 'User updated successfully'}), 200
    else:
        return jsonify({'message': 'User not found'}), 404

CORS(app, origins=["http://localhost:5500"])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)

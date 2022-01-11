from flask import Flask, request, jsonify 
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash
import os 
from functools import wraps
import jwt
import datetime


app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+os.path.join(basedir,'final.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
	id = db.Column(db.Integer,primary_key=True)
	name = db.Column(db.String(50))
	password = db.Column(db.String(50))
	isAdmin = db.Column(db.Boolean)

class Product(db.Model):
	id = db.Column(db.Integer,primary_key=True)
	name = db.Column(db.String(50))
	category = db.Column(db.String(50))
	qty = db.Column(db.Integer)

def token_required(f):
	@wraps(f)
	def wrapper(*args,**kwargs):
		if 'access-token' in request.headers:
			token = request.headers.get('access-token')
		else:
			return jsonify({'Error':'Token Missing'})
		try:
			data = jwt.decode(token,app.config['SECRET_KEY'])
			user = User.query.filter_by(name=data['name']).first()
		except:
			return jsonify({'Error':'Token Invalid'})

		return f(user,*args,**kwargs)

	return wrapper	


@app.route('/myapp/register',methods=['POST'])
def register():
	data = request.get_json()
	name = data['name']
	hashed_password = generate_password_hash(data['password'])
	isAdmin = data['isAdmin']
	user = User(name=name,password=hashed_password,isAdmin=isAdmin)
	db.session.add(user)
	db.session.commit()
	return jsonify({name:'Successfully added'})


@app.route('/myapp/login')
def login():
	auth = request.authorization
	if not auth or not auth.username or not auth.password:
		return jsonify({'Error':'Login Info Missing'})
	name = auth.username 
	user = User.query.filter_by(name=name).first()
	if not user:
		return jsonify({'Error':'No Such User Found'})
	if check_password_hash(user.password,auth.password):
		token = jwt.encode({'name':name,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30)},app.config['SECRET_KEY'])
		return jsonify({'Token':token.decode('UTF-8')})
	return jsonify({'Error':'Incorrect Password'})



@app.route('/myapp/create',methods=['POST'])
@token_required
def create(user):
	# return jsonify({'Status':user.isAdmin})
	if not user.isAdmin:
		return jsonify({'Error':'You are not an admin'})
	data = request.get_json()
	name = data['name']
	category = data['category']
	qty = data['qty']
	prod = Product(name=name,qty=qty,category=category)
	db.session.add(prod)
	db.session.commit()
	return jsonify({'Status':'Successfully Added'})


@app.route('/myapp/viewall',methods=['GET'])
@token_required
def viewall(user):
	output= []
	products = Product.query.all()
	for prod in products:
		data = {}
		data['id'] = prod.id
		data['name'] = prod.name
		data['qty'] = prod.qty
		output.append(data)
	return jsonify({'Products':output})



@app.route('/myapp/viewone/<prod_id>',methods=['GET'])
@token_required
def viewone(user,prod_id):
	product = Product.query.filter_by(id=prod_id).first()
	if not product:
		return jsonify({'Error':'No Such Product Found'})
	data = {}
	data['id'] = product.id 
	data['name'] = product.name 
	data['qty'] = product.qty 
	return jsonify({'Product' : data})



@app.route('/myapp/delete/<prod_id>',methods=['DELETE'])
@token_required
def delete(user,prod_id):
	# return jsonify({'status':user.name})
	if not user.isAdmin:
		return jsonify({'Error':'You are not an admin'})
	product = Product.query.filter_by(id=prod_id).first()
	if not product:
		return jsonify({'Error':'No Such Product Found'})
	db.session.delete(product)
	db.session.commit()
	return jsonify({product.name:'Successfully Deleted'})
	

@app.route('/myapp/update/<prod_id>',methods=['PUT'])
@token_required
def update(user,prod_id):
	if not user.isAdmin:
		return jsonify({'Error':'You are not an admin'})
	product = Product.query.filter_by(id=prod_id).first()
	if not product:
		return jsonify({'Error':'No Such Product Found'})
	data = request.get_json()
	product.qty = data['qty']
	db.session.commit()
	return jsonify({'Status':'Successfully Updated'})


if __name__ == '__main__':
	app.run(debug=True)


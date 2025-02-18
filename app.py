from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, FloatField, IntegerField,  TextAreaField
from wtforms.validators import InputRequired, Length
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)  # Initialize Flask-Bcrypt
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), default='user')  # Role-based access (user/admin)
    
    products = db.relationship('Product', back_populates='owner', lazy=True)
    
    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, default=0)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Admin who created the product
    
    owner = db.relationship('User', back_populates='products')


class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    feedback = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Add foreign key to User
    user = db.relationship('User', backref='feedbacks', lazy=True)  # Define relationship with User


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=150)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=150)])

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=150)])
    email = StringField('Email', validators=[InputRequired(), Length(min=6, max=150)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=150)])

class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[InputRequired()])
    price = FloatField('Price', validators=[InputRequired()])
    stock = IntegerField('Stock', validators=[InputRequired()])

class FeedbackForm(FlaskForm):
    feedback = TextAreaField('Feedback', validators=[InputRequired()])

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[InputRequired()])
    new_password = PasswordField('New Password', validators=[InputRequired(), Length(min=8, max=150)])
    confirm_password = PasswordField('Confirm New Password', validators=[InputRequired(), Length(min=8, max=150)])




@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your username and/or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        new_user = User(username=form.username.data, email=form.email.data)
        new_user.set_password(form.password.data)  # Store only the password (hashed) in the database
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully. Please login!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out!', 'success')
    return redirect(url_for('index'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        if current_user.check_password(form.current_password.data):
            if form.new_password.data == form.confirm_password.data:
                current_user.set_password(form.new_password.data)
                db.session.commit()
                flash('Your password has been changed successfully!', 'success')
            else:
                flash('New passwords do not match!', 'danger')
        else:
            flash('Current password is incorrect.', 'danger')

    return render_template('change_password.html', form=form)


@app.route('/products')
def products():
    all_products = Product.query.all()  # Fetch all products
    return render_template('products.html', products=all_products)  # Pass products to the template


@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if current_user.role != 'admin':
        flash('Only admins can add products!', 'danger')
        return redirect(url_for('index'))

    form = ProductForm()
    if form.validate_on_submit():
        # Create a new product with the form data
        new_product = Product(
            name=form.name.data,
            price=form.price.data,
            stock=form.stock.data,
            owner_id=current_user.id
        )
        
        # Add product to the database
        db.session.add(new_product)
        db.session.commit()

        # Flash a success message
        flash('Product added successfully!', 'success')
        
        # Redirect to the products page after adding the product
        return redirect(url_for('add_product'))

    # If the form wasn't submitted, return the template
    return render_template('add_product.html', form=form)



@app.route('/buy_product/<int:product_id>', methods=['POST'])
@login_required
def buy_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    if product.stock > 0:
        product.stock -= 1
        db.session.commit()
        flash(f'You have successfully bought {product.name}!', 'success')
    else:
        flash(f'{product.name} is out of stock!', 'danger')
        
    return redirect(url_for('products'))

@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    
    print(f"Attempting to delete product with ID: {product_id}")  # Debugging line
    if current_user.role != 'admin':
        flash('You do not have permission to delete products.', 'danger')
        return redirect(url_for('products'))

    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    
    flash(f'Product {product.name} has been deleted.', 'success')
    return redirect(url_for('products'))

@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    form = FeedbackForm()
    if form.validate_on_submit():
        new_feedback = Feedback(feedback=form.feedback.data, user_id=current_user.id)  # Set user_id
        db.session.add(new_feedback)
        db.session.commit()
        flash('Your feedback has been submitted!', 'success')
        return redirect(url_for('feedback'))
    
    return render_template('feedback.html', form=form)

@app.route('/view_feedback', methods=['GET', 'POST'])
@login_required
def view_feedback():
    if current_user.role != 'admin':
        flash("You don't have permission to view feedback.", 'danger')
        return redirect(url_for('index'))

    feedback_list = Feedback.query.all()  # Get all feedback

    # Handle feedback deletion
    if request.method == 'POST':
        feedback_id = request.form.get('feedback_id')
        if feedback_id:
            feedback_to_delete = Feedback.query.get(feedback_id)
            if feedback_to_delete:
                db.session.delete(feedback_to_delete)
                db.session.commit()
                flash("Feedback has been deleted.", 'success')  # Flash message after deletion
            else:
                flash("Feedback not found.", 'danger')

        return redirect(url_for('view_feedback'))

    return render_template('view_feedback.html', feedback_list=feedback_list)


@app.route('/delete_feedback/<int:feedback_id>', methods=['POST'])
@login_required
def delete_feedback(feedback_id):
    # Ensure that only admin can delete feedback
    if current_user.role != 'admin':
        flash('You do not have permission to delete feedback.', 'danger')
        return redirect(url_for('index'))

    # Get the feedback entry by ID
    feedback_to_delete = Feedback.query.get(feedback_id)

    # Check if feedback exists
    if feedback_to_delete:
        db.session.delete(feedback_to_delete)
        db.session.commit()
        flash('Feedback deleted successfully!', 'success')
    else:
        flash('Feedback not found.', 'danger')

    # Redirect back to the view feedback page
    return redirect(url_for('view_feedback'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  
    app.run(debug=True)

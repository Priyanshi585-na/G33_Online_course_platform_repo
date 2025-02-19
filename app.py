from functools import wraps
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os

app = Flask(__name__) 

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/pricing")
def pricing():
    return render_template("pricing.html")

@app.route("/teach")
def teach():
    return render_template("teach.html")

@app.route("/teachy")
@login_required
def teachy():
    return render_template("teachy.html")

@app.route("/about")
def about():
    return render_template("aboutus.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")


basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "my_secret_key"  


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  


class User(db.Model, UserMixin):
    tablename = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
    mobile = db.Column(db.String(15), nullable=False)
    role = db.Column(db.String(50), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

with app.app_context():
    db.create_all()


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid credentials!", "danger")

    return render_template("login.html")

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        mobile = request.form.get("mobile")
        role = request.form.get("role")

       
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("register"))

        
        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for("register"))

        
        if len(mobile) != 10 or not mobile.isdigit():
            flash("Mobile number must be exactly 10 digits!", "danger")
            return redirect(url_for("register"))

      
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return redirect(url_for("register"))

        if not any(char.isdigit() for char in password):
            flash("Password must contain at least one digit.", "danger")
            return redirect(url_for("register"))

        if not any(char.isalpha() for char in password):
            flash("Password must contain at least one letter.", "danger")
            return redirect(url_for("register"))

        if not any(char in "@$!%?&" for char in password):
            flash("Password must contain at least one special character (@$!%?&).", "danger")
            return redirect(url_for("register"))
            
        
        
        new_user = User(name=name, email=email, mobile=mobile, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for("index"))



# #login required
@app.route('/home')
@login_required
def home():
    data = User.query.all()
    return render_template('home.html', data= data, user=current_user)

@app.route('/python_courses')
@login_required
def python_courses():
    return render_template('python_courses.html')

@app.route('/development')
@login_required
def development():
    return render_template('development.html')

@app.route('/IT_Software')
@login_required
def IT_Software():
    return render_template('IT_Software.html')

@app.route('/programming_languages')
@login_required
def programming_languages ():
    return render_template('programming_languages.html')

@app.route('/othersoftware')
@login_required
def othersoftware ():
    return render_template('othersoftware.html')

@app.route('/datasciencecourses')
@login_required
def datasciencecourses ():
    return render_template('datasciencecourses.html')

@app.route('/javacourses')
@login_required
def javacourses ():
    return render_template('javacourses.html')

@app.route('/dataanalysiscourses')
@login_required
def dataanalysiscourses():
    return render_template('dataanalysiscourses.html')


@app.route('/user')
@login_required
def user():
    data = User.query.all()
    return render_template('user.html', data=data, user=current_user)

@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    user = db.session.get(User, id)
    if user is None:
        return "User  not found", 404

    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        mobile = request.form.get("mobile")
        
       
        user.name = name
        user.email = email
        user.mobile = mobile
        
        db.session.commit()
        return redirect(url_for("user"))

    return render_template('update.html', user=user)


if __name__ == "__main__":
    app.run(debug = True)
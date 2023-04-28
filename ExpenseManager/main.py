from flask import Flask, request, render_template, url_for, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()
login_manager = LoginManager()

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config["SECRET_KEY"] = "shaklfhzhjhgjjjfjjfjjf1233333"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///Expense_manager_db.sqlite"

db.init_app(app)
login_manager.init_app(app)


class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)

    def __init__(self, name, email):
        self.name = name
        self.email = email

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def __repr__(self):
        return f"Users <{Users.name}>"


class Expenses(db.Model):
    __tablename__ = "expenses"
    id = db.Column(db.Integer, primary_key=True)
    merchant = db.Column(db.String, nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    date = db.Column(db.String, nullable=False)
    remark = db.Column(db.String, nullable=False)

    def __init__(self, merchant, amount, date, remark):
        self.merchant = merchant
        self.amount = amount
        self.date = date
        self.remark = remark

    def __repr__(self):
        return f"Expenses<{Expenses.merchant}>"


@app.route("/", methods=['Get', 'POST'])
def signup():
    if request.method == "POST":
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        check_email = Users.query.filter_by(email=email).first()
        if check_email == email:
            return f"Email Taken"
        if password == confirm_password:
            new_user = Users(name, email)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        else:
            return "invalid confirm_password"
    return render_template('signup.html')


@app.route('/login', methods=['Get', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        check_mail = Users.query.filter_by(email=email).first()
        if check_mail:
            password = request.form['password']
            check_user = Users.query.filter_by(email=email).first()
            if check_user and check_user.check_password(password):
                login_user(check_user)
                return redirect(url_for('new', current_user=current_user, Tittle=dashboard))
            else:
                return "Invalid Password"
        else:
            return "Invalid Email"
    return render_template('login.html')


@app.route("/dashboard", methods=['GET', 'POST'])
def dashboard():
    if request.method == 'POST':
        merchant = request.form['merchant']
        amount = request.form['amount']
        date = request.form['date']
        remark = request.form['remark']

        save_expenses = Expenses(merchant, amount, date, remark)
        db.session.add(save_expenses)
        db.session.commit()
        return redirect(url_for('new', order=save_expenses))
    return render_template('new.html')


@app.route("/new", methods=['GET', 'POST'])
def new():
    expense = Expenses.query.all()
    all_total = 0
    for exp in expense:
        all_total += exp.amount
    return render_template('new.html', order=expense, total=all_total)


@app.route('/filter', methods=['GET', 'POST'])
def from_filter():
    if request.method == 'POST':
        date1 = request.form['date1']
        date2 = request.form['date2']
        user = Expenses.query.filter(Expenses.date.between(date1, date2)).order_by(Expenses.date.desc())
        all_total = 0
        for use in user:
            all_total += use.amount
        return render_template('filter.html', order=user, total=all_total)
    return render_template('new.html')


@app.route("/delete")
def delete():
    user_id = request.args.get('view')
    single = Expenses.query.filter_by(id=user_id).first()

    db.session.delete(single)
    db.session.commit()
    return redirect(url_for('new'))


@app.route('/edit', methods=['GET', 'POST'])
def edit():
    if request.method == 'POST':
        id = request.form['id']
        merchant = request.form['merchant']
        amount = request.form['amount']
        date = request.form['date']
        remark = request.form['remark']

        single = Expenses.query.filter_by(id=id).first()
        single.merchant = merchant
        single.amount = amount
        single.date = date
        single.remark = remark
        db.session.add(single)
        db.session.commit()
        return redirect(url_for('new'))

    user_id = request.args.get('view')
    single = Expenses.query.filter_by(id=user_id).first()
    return render_template('edit.html', record=single)


@app.route("/logout")
def logout():
    logout_user()
    return render_template("login.html")


@login_manager.user_loader
def load_user(users_id):
    if users_id is not None:
        return Users.query.get(users_id)
    return None


@login_manager.unauthorized_handler
def unauthorized():
    flash("Login is required")
    return redirect(url_for('logout'))


with app.app_context():
    db.create_all()
if __name__ == '__main__':
    app.run(debug=True)

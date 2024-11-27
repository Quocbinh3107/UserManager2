from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Đặt khóa bí mật cho phiên làm việc

# Cấu hình cơ sở dữ liệu
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Định nghĩa mô hình User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # Mặc định là người dùng bình thường

# Trang chính
@app.route('/')
def home():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return render_template('welcome.html', user=user)  # Render trang chào mừng với tên người dùng
    return '''
    <html>
    <head>
        <title>Home</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f4f4f9;
                margin: 0;
                padding: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                text-align: center;
            }
            .welcome-message {
                font-size: 24px;
                margin-bottom: 20px;
            }
            .link-container a {
                font-size: 18px;
                margin: 10px 20px;
                padding: 10px 20px;
                background-color: #4caf50;
                color: white;
                text-decoration: none;
                border-radius: 5px;
                transition: background-color 0.3s;
            }
            .link-container a:hover {
                background-color: #45a049;
            }
        </style>
    </head>
    <body>
        <div class="welcome-message">
            Welcome to User Management System!<br>
        </div>
        <div class="link-container">
            <a href='/login'>Login</a>
            <a href='/register'>Register</a>
        </div>
    </body>
    </html>
    ''' 

# Đăng ký
@app.route('/register', methods=['GET', 'POST'])
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role', 'user')  # Mặc định là "user"

        # Kiểm tra nếu email hoặc username đã tồn tại
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'danger')
            return redirect(url_for('register'))

        # Mã hóa mật khẩu
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

        # Tạo người dùng mới
        new_user = User(username=username, email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Đăng nhập
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Kiểm tra thông tin người dùng
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            
            # Điều hướng dựa trên vai trò của người dùng
            if user.role == 'admin':
                flash(f'Welcome Admin, {user.username}!', 'success')
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'manager':
                flash(f'Welcome Manager, {user.username}!', 'success')
                return redirect(url_for('manager_dashboard'))
            else:  # Mặc định là user
                flash(f'Welcome User, {user.username}!', 'success')
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid email or password!', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

# Trang dashboard cho admin
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role == 'admin':
            return render_template('admin_dashboard.html', user=user)
        else:
            flash('Access denied. Admins only.', 'danger')
            return redirect(url_for('home'))
    flash('You need to login first.', 'danger')
    return redirect(url_for('login'))

# Trang dashboard cho người dùng
@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role == 'user':
            return render_template('user_dashboard.html', user=user)
        else:
            flash('Access denied.', 'danger')
            return redirect(url_for('home'))
    flash('You need to login first.', 'danger')
    return redirect(url_for('login'))

# Trang dashboard cho manager
@app.route('/manager_dashboard')
def manager_dashboard():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role == 'manager':
            return render_template('manager_dashboard.html', user=user)
        else:
            flash('Access denied. Managers only.', 'danger')
            return redirect(url_for('home'))
    flash('You need to login first.', 'danger')
    return redirect(url_for('login'))

# Đăng xuất
@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Xóa thông tin người dùng khỏi session
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# Danh sách người dùng (chỉ cho admin)
@app.route('/users')
def users():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role == 'admin':  
            all_users = User.query.all()
            return render_template('users.html', users=all_users)
        else:
            flash('Access denied. Only admin can view user list.', 'danger')
            return redirect(url_for('home'))
    flash('You need to login first.', 'danger')
    return redirect(url_for('login'))
#Thêm người dùng
@app.route('/add_user', methods=['GET', 'POST'])
def add_new_user():
    if 'user_id' not in session:  # Kiểm tra xem người dùng đã đăng nhập chưa
        flash('You need to login first.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if user.role != 'admin':  # Chỉ admin mới được phép thêm người dùng
        flash('Access denied. Only admins can add new users.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        # Lấy dữ liệu từ form
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        # Kiểm tra nếu username hoặc email đã tồn tại
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('add_new_user'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'danger')
            return redirect(url_for('add_new_user'))

        # Mã hóa mật khẩu và tạo người dùng mới
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        new_user = User(username=username, email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('New user added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('add_new_user.html')  # Trang HTML để hiển thị form thêm user
#Edit user
@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session:
        flash('You need to login first.', 'danger')
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])
    if current_user.role != 'admin':
        flash('Access denied. Only admins can edit users.', 'danger')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)  # Lấy thông tin người dùng
    if request.method == 'POST':
        # Cập nhật thông tin người dùng
        user.username = request.form['username']
        user.email = request.form['email']
        user.role = request.form['role']

        db.session.commit()  # Lưu thay đổi vào DB
        flash('User updated successfully!', 'success')
        return redirect(url_for('users'))

    return render_template('edit_user.html', user=user)
#Xóa user
@app.route('/delete_user/<int:user_id>', methods=['GET'])
def delete_user(user_id):
    if 'user_id' not in session:
        flash('You need to login first.', 'danger')
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])
    if current_user.role != 'admin':
        flash('Access denied. Only admins can delete users.', 'danger')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    return render_template('confirm_delete_user.html', user=user)
#Trang xác nhận xóa
@app.route('/delete_user_confirmed/<int:user_id>', methods=['GET'])
def delete_user_confirmed(user_id):
    if 'user_id' not in session:
        flash('You need to login first.', 'danger')
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])
    if current_user.role != 'admin':
        flash('Access denied. Only admins can delete users.', 'danger')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)  # Xóa người dùng
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('users'))

# Tạo cơ sở dữ liệu
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)

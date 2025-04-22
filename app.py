import os
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from functools import wraps

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-secret-key-123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Декоратор для проверки прав администратора
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)

    return decorated_function


# Модель пользователя
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)


# Модель категории
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    products = db.relationship('Product', backref='category', lazy=True)


# Модель складской ячейки
class StorageCell(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), nullable=False, unique=True)
    description = db.Column(db.String(200))
    capacity = db.Column(db.Integer, nullable=False)
    products = db.relationship('Product', backref='cell', lazy=True)


# Модель продукта
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(100))
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    cell_id = db.Column(db.Integer, db.ForeignKey('storage_cell.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# Объединенный маршрут
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    stats = {
        'products_count': Product.query.count(),
        'categories_count': Category.query.count(),
        'cells_count': StorageCell.query.count(),
        'inventory_value': db.session.query(db.func.sum(Product.price * Product.quantity)).scalar() or 0,
        'low_stock': Product.query.filter(Product.quantity < 10).count()
    }
    recent_products = Product.query.order_by(Product.updated_at.desc()).limit(5).all()
    return render_template('dashboard.html',
                         stats=stats,
                         recent_products=recent_products)


# Инициализация базы данных
def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# Вспомогательные функции
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def save_uploaded_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return filename
    return None


# Маршруты аутентификации
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            next_page = request.args.get('next')
            flash('Вы успешно вошли в систему', 'success')
            return redirect(next_page or url_for('dashboard'))
        flash('Неверное имя пользователя или пароль', 'danger')
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('login'))


@app.route('/api/search-by-barcode', methods=['POST'])
@login_required
def search_by_barcode():
    data = request.get_json()
    if not data or 'barcode' not in data:
        return jsonify({'error': 'Штрихкод не указан'}), 400

    barcode = Barcode.query.filter_by(barcode=data['barcode']).first()
    if not barcode:
        return jsonify({'error': 'Товар с таким штрихкодом не найден'}), 404

    product = barcode.product
    return jsonify({
        'id': product.id,
        'name': product.name,
        'price': product.price,
        'quantity': product.quantity,
        'category': product.category.name if product.category else None
    })

# Маршруты для товаров
@app.route('/products')
@login_required
def products():
    page = request.args.get('page', 1, type=int)
    search = request.form.get('search', request.args.get('search', '').strip())
    category_id = request.args.get('category_id', type=int)

    query = Product.query

    if search:
        query = query.filter(Product.name.ilike(f'%{search}%'))
    if category_id:
        query = query.filter_by(category_id=category_id)

    products = query.order_by(Product.name).paginate(page=page, per_page=10)
    categories = Category.query.all()
    return render_template('products/list.html', products=products, categories=categories, search=search)


@app.route('/products/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_product():
    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
            if not name:
                flash('Название товара обязательно', 'danger')
                return redirect(url_for('add_product'))

            if Product.query.filter(Product.name.ilike(name)).first():
                flash('Товар с таким названием уже существует', 'danger')
                return redirect(url_for('add_product'))

            price = float(request.form.get('price', 0))
            quantity = int(request.form.get('quantity', 0))
            if price <= 0 or quantity < 0:
                flash('Цена и количество должны быть положительными', 'danger')
                return redirect(url_for('add_product'))

            category_id = int(request.form.get('category', 0))
            cell_id = int(request.form.get('cell', 0)) or None

            if cell_id:
                cell = StorageCell.query.get_or_404(cell_id)
                current_occupancy = sum(p.quantity for p in cell.products)
                if current_occupancy + quantity > cell.capacity:
                    flash(f'Ячейка {cell.code} может вместить только {cell.capacity - current_occupancy} единиц',
                          'danger')
                    return redirect(url_for('add_product'))

            image = None
            if 'image' in request.files:
                image = save_uploaded_file(request.files['image'])

            product = Product(
                name=name,
                description=request.form.get('description', '').strip(),
                price=price,
                quantity=quantity,
                category_id=category_id,
                cell_id=cell_id,
                image=image
            )

            db.session.add(product)
            db.session.commit()
            flash('Товар успешно добавлен', 'success')
            return redirect(url_for('products'))

        except ValueError:
            flash('Некорректные данные в форме', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при добавлении товара: {str(e)}', 'danger')

    categories = Category.query.all()
    cells = StorageCell.query.all()
    return render_template('products/add.html', categories=categories, cells=cells)


@app.route('/products/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_product(id):
    product = Product.query.get_or_404(id)

    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
            if not name:
                flash('Название товара обязательно', 'danger')
                return redirect(url_for('edit_product', id=id))

            existing = Product.query.filter(Product.name.ilike(name), Product.id != id).first()
            if existing:
                flash('Товар с таким названием уже существует', 'danger')
                return redirect(url_for('edit_product', id=id))

            price = float(request.form.get('price', 0))
            quantity = int(request.form.get('quantity', 0))
            if price <= 0 or quantity < 0:
                flash('Цена и количество должны быть положительными', 'danger')
                return redirect(url_for('edit_product', id=id))

            category_id = int(request.form.get('category', 0))
            cell_id = int(request.form.get('cell', 0)) or None

            if cell_id and (product.cell_id != cell_id or product.quantity != quantity):
                cell = StorageCell.query.get_or_404(cell_id)
                current_occupancy = sum(p.quantity for p in cell.products if p.id != id)
                if current_occupancy + quantity > cell.capacity:
                    flash(f'Ячейка {cell.code} может вместить только {cell.capacity - current_occupancy} единиц',
                          'danger')
                    return redirect(url_for('edit_product', id=id))

            if 'image' in request.files:
                new_image = save_uploaded_file(request.files['image'])
                if new_image:
                    if product.image and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], product.image)):
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], product.image))
                    product.image = new_image

            product.name = name
            product.description = request.form.get('description', '').strip()
            product.price = price
            product.quantity = quantity
            product.category_id = category_id
            product.cell_id = cell_id

            db.session.commit()
            flash('Товар успешно обновлен', 'success')
            return redirect(url_for('products'))

        except ValueError:
            flash('Некорректные данные в форме', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при обновлении товара: {str(e)}', 'danger')

    categories = Category.query.all()
    cells = StorageCell.query.all()
    return render_template('products/edit.html', product=product, categories=categories, cells=cells)


@app.route('/products/<int:id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_product(id):
    product = Product.query.get_or_404(id)
    try:
        if product.image and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], product.image)):
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], product.image))

        db.session.delete(product)
        db.session.commit()
        flash('Товар успешно удален', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при удалении товара: {str(e)}', 'danger')

    return redirect(url_for('products'))


# Маршруты для категорий (аналогично для ячеек)
@app.route('/categories')
@login_required
def categories():
    categories = Category.query.order_by(Category.name).all()
    return render_template('categories/list.html', categories=categories)


@app.route('/categories/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_category():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash('Название категории обязательно', 'danger')
            return redirect(url_for('add_category'))

        if Category.query.filter(Category.name.ilike(name)).first():
            flash('Категория с таким названием уже существует', 'danger')
            return redirect(url_for('add_category'))

        category = Category(name=name)
        db.session.add(category)
        db.session.commit()
        flash('Категория успешно добавлена', 'success')
        return redirect(url_for('categories'))

    return render_template('categories/add.html')


@app.route('/categories/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_category(id):
    category = Category.query.get_or_404(id)

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash('Название категории обязательно', 'danger')
            return redirect(url_for('edit_category', id=id))

        existing = Category.query.filter(Category.name.ilike(name), Category.id != id).first()
        if existing:
            flash('Категория с таким названием уже существует', 'danger')
            return redirect(url_for('edit_category', id=id))

        category.name = name
        db.session.commit()
        flash('Категория успешно обновлена', 'success')
        return redirect(url_for('categories'))

    return render_template('categories/edit.html', category=category)


@app.route('/categories/<int:id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_category(id):
    category = Category.query.get_or_404(id)

    if Product.query.filter_by(category_id=id).count() > 0:
        flash('Нельзя удалить категорию, в которой есть товары', 'danger')
        return redirect(url_for('categories'))

    db.session.delete(category)
    db.session.commit()
    flash('Категория успешно удалена', 'success')
    return redirect(url_for('categories'))


# Маршруты для складских ячеек (аналогично категориям)
@app.route('/cells')
@login_required
def cells():
    cells = StorageCell.query.order_by(StorageCell.code).all()
    return render_template('cells/list.html', cells=cells)


@app.route('/cells/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_cell():
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        if not code:
            flash('Код ячейки обязателен', 'danger')
            return redirect(url_for('add_cell'))

        if StorageCell.query.filter(StorageCell.code.ilike(code)).first():
            flash('Ячейка с таким кодом уже существует', 'danger')
            return redirect(url_for('add_cell'))

        try:
            capacity = int(request.form.get('capacity', 0))
            if capacity <= 0:
                flash('Вместимость должна быть положительной', 'danger')
                return redirect(url_for('add_cell'))

            cell = StorageCell(
                code=code,
                description=request.form.get('description', '').strip(),
                capacity=capacity
            )

            db.session.add(cell)
            db.session.commit()
            flash('Ячейка успешно добавлена', 'success')
            return redirect(url_for('cells'))

        except ValueError:
            flash('Некорректное значение вместимости', 'danger')

    return render_template('cells/add.html')


@app.route('/cells/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_cell(id):
    cell = StorageCell.query.get_or_404(id)

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        if not code:
            flash('Код ячейки обязателен', 'danger')
            return redirect(url_for('edit_cell', id=id))

        existing = StorageCell.query.filter(StorageCell.code.ilike(code), StorageCell.id != id).first()
        if existing:
            flash('Ячейка с таким кодом уже существует', 'danger')
            return redirect(url_for('edit_cell', id=id))

        try:
            capacity = int(request.form.get('capacity', 0))
            if capacity <= 0:
                flash('Вместимость должна быть положительной', 'danger')
                return redirect(url_for('edit_cell', id=id))

            current_occupancy = sum(p.quantity for p in cell.products)
            if capacity < current_occupancy:
                flash(f'Новая вместимость ({capacity}) меньше текущего заполнения ({current_occupancy})', 'danger')
                return redirect(url_for('edit_cell', id=id))

            cell.code = code
            cell.description = request.form.get('description', '').strip()
            cell.capacity = capacity

            db.session.commit()
            flash('Ячейка успешно обновлена', 'success')
            return redirect(url_for('cells'))

        except ValueError:
            flash('Некорректное значение вместимости', 'danger')

    return render_template('cells/edit.html', cell=cell)


@app.route('/cells/<int:id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_cell(id):
    cell = StorageCell.query.get_or_404(id)

    if cell.products:
        flash('Нельзя удалить ячейку, в которой есть товары', 'danger')
        return redirect(url_for('cells'))

    db.session.delete(cell)
    db.session.commit()
    flash('Ячейка успешно удалена', 'success')
    return redirect(url_for('cells'))


# Запуск приложения
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    init_db()
    app.run(debug=True)
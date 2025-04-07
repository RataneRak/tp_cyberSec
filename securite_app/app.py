from flask import Flask, render_template, request, redirect, url_for, session, flash, g
import sqlite3
import os
from config import Config
import logging
from functools import wraps

# Configuration du logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

app = Flask(__name__)
app.config.from_object(Config)

# Fonction pour obtenir une connexion à la base de données
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

# Fonction pour fermer la connexion à la base de données
@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Décorateur pour vérifier si l'utilisateur est connecté
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Veuillez vous connecter pour accéder à cette page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes pour les pages principales
@app.route('/')
def index():
    db = get_db()
    products = db.execute('SELECT * FROM products').fetchall()
    return render_template('index.html', products=products)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Version vulnérable: pas de protection contre les injections SQL
        db = get_db()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        logging.info(f"Exécution de la requête: {query}")
        user = db.execute(query).fetchone()
        
        if user:
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            
            # Configuration des cookies sans sécurité (vulnérable au XSS)
            response = redirect(url_for('index'))
            return response
        else:
            error = 'Nom d\'utilisateur ou mot de passe incorrect.'
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        db = get_db()
        error = None
        
        if not username:
            error = 'Nom d\'utilisateur requis.'
        elif not password:
            error = 'Mot de passe requis.'
        elif not email:
            error = 'Email requis.'
        elif db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            error = f'L\'utilisateur {username} est déjà enregistré.'
        
        if error is None:
            db.execute(
                'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                (username, password, email)
            )
            db.commit()
            flash('Inscription réussie! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))
        
        flash(error, 'error')
    
    return render_template('register.html')

@app.route('/product/<int:product_id>', methods=['GET', 'POST'])
def product(product_id):
    db = get_db()
    product = db.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    
    if product is None:
        flash('Produit introuvable.', 'error')
        return redirect(url_for('index'))
    
    # Récupération des commentaires pour le produit
    comments = db.execute(
        'SELECT c.id, c.content, c.created_at, u.username '
        'FROM comments c JOIN users u ON c.user_id = u.id '
        'WHERE c.product_id = ? '
        'ORDER BY c.created_at DESC',
        (product_id,)
    ).fetchall()
    
    # Ajout de commentaire
    if request.method == 'POST' and 'user_id' in session:
        content = request.form['content']
        user_id = session['user_id']
        
        # Insertion du commentaire sans échapper le contenu (vulnérable au XSS)
        db.execute(
            'INSERT INTO comments (product_id, user_id, content) VALUES (?, ?, ?)',
            (product_id, user_id, content)
        )
        db.commit()
        
        # Log pour détecter les tentatives d'attaque XSS
        logging.info(f"Nouveau commentaire par l'utilisateur {session['username']} sur le produit {product_id}: {content}")
        
        return redirect(url_for('product', product_id=product_id))
    
    return render_template('product.html', product=product, comments=comments)

@app.route('/admin')
@login_required
def admin():
    if not session.get('is_admin'):
        flash('Accès non autorisé.', 'error')
        return redirect(url_for('index'))
    
    db = get_db()
    users = db.execute('SELECT * FROM users').fetchall()
    products = db.execute('SELECT * FROM products').fetchall()
    comments = db.execute(
        'SELECT c.id, c.content, c.created_at, u.username, p.name '
        'FROM comments c '
        'JOIN users u ON c.user_id = u.id '
        'JOIN products p ON c.product_id = p.id '
        'ORDER BY c.created_at DESC'
    ).fetchall()
    
    return render_template('admin.html', users=users, products=products, comments=comments)

if __name__ == '__main__':
    # Vérifier si la base de données existe, sinon l'initialiser
    if not os.path.exists(app.config['DATABASE']):
        from database.init_db import init_db
        init_db()
    
    app.run(debug=True)
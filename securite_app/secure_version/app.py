from flask import Flask, render_template, request, redirect, url_for, session, flash, g, escape
import sqlite3
import os
import re
import logging
import time
import random
import hashlib
from functools import wraps
import html
from datetime import datetime

# Configuration du logging
logging.basicConfig(
    filename='secure_app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.urandom(24),
    DATABASE=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database.db'),
    SECURE_COOKIES=True,
    CSP_ENABLED=True,
    MAX_LOGIN_ATTEMPTS=3,
    LOGIN_TIMEOUT=300
)

# Dictionnaire pour suivre les tentatives de connexion
login_attempts = {}
blocked_ips = {}

# Fonction pour obtenir l'adresse IP du client
def get_client_ip():
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ.get('HTTP_X_FORWARDED_FOR')
    else:
        return request.environ.get('REMOTE_ADDR')

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

# Fonction pour hacher un mot de passe
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()  # Génère un salt aléatoire
    
    # Utilise PBKDF2 avec SHA-256 pour hacher le mot de passe
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${hashed.hex()}"

# Fonction pour vérifier un mot de passe
def verify_password(stored_password, provided_password):
    salt, hashed = stored_password.split('$')
    return stored_password == hash_password(provided_password, salt)

# Décorateur pour vérifier si l'utilisateur est connecté
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Veuillez vous connecter pour accéder à cette page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Middleware pour appliquer CSP
@app.after_request
def add_security_headers(response):
    if app.config['CSP_ENABLED']:
        # Content Security Policy pour bloquer les scripts externes
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none';"
    
    # D'autres en-têtes de sécurité
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    return response

# Routes pour les pages principales
@app.route('/')
def index():
    db = get_db()
    products = db.execute('SELECT * FROM products').fetchall()
    return render_template('index.html', products=products)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    client_ip = get_client_ip()
    
    # Vérifie si l'IP est bloquée
    if client_ip in blocked_ips:
        block_time = blocked_ips[client_ip]
        current_time = time.time()
        
        if current_time < block_time:
            remaining = int(block_time - current_time)
            return render_template('login.html', error=f"Trop de tentatives échouées. Réessayez dans {remaining} secondes.")
        else:
            # Débloquer l'IP si le temps est écoulé
            del blocked_ips[client_ip]
            if client_ip in login_attempts:
                del login_attempts[client_ip]
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Validation des entrées
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            error = "Format de nom d'utilisateur non valide."
            flash(error, 'error')
            return render_template('login.html', error=error)
        
        # Version sécurisée: utilisation de requêtes paramétrées
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        # Vérification du mot de passe (dans une application réelle, il serait haché)
        if user and user['password'] == password:  # Simplifié pour le TP
            # Réinitialiser les tentatives de connexion
            if client_ip in login_attempts:
                del login_attempts[client_ip]
            
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            
            # Configuration sécurisée des cookies
            response = redirect(url_for('index'))
            if app.config['SECURE_COOKIES']:
                response.set_cookie('session', request.cookies.get('session'), httponly=True, secure=True, samesite='Lax')
            
            # Journalisation de la connexion réussie
            logging.info(f"Connexion réussie pour l'utilisateur {username} depuis {client_ip}")
            
            return response
        else:
            # Gestion des tentatives de connexion échouées
            if client_ip not in login_attempts:
                login_attempts[client_ip] = 1
            else:
                login_attempts[client_ip] += 1
            
            # Bloquer l'IP après MAX_LOGIN_ATTEMPTS tentatives
            if login_attempts[client_ip] >= app.config['MAX_LOGIN_ATTEMPTS']:
                blocked_ips[client_ip] = time.time() + app.config['LOGIN_TIMEOUT']
                logging.warning(f"IP {client_ip} bloquée après {login_attempts[client_ip]} tentatives de connexion échouées")
                return render_template('login.html', error=f"Trop de tentatives échouées. Réessayez dans {app.config['LOGIN_TIMEOUT']} secondes.")
            
            error = 'Nom d\'utilisateur ou mot de passe incorrect.'
            logging.warning(f"Tentative de connexion échouée pour l'utilisateur {username} depuis {client_ip}")
    
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
        
        # Validation des entrées
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            flash("Format de nom d'utilisateur non valide.", 'error')
            return render_template('register.html')
        
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            flash("Format d'email non valide.", 'error')
            return render_template('register.html')
        
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
            # Dans une application réelle, nous hasherions le mot de passe
            # hashed_password = hash_password(password)
            db.execute(
                'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                (username, password, email)  # Simplifié pour le TP
            )
            db.commit()
            
            logging.info(f"Nouvel utilisateur enregistré: {username}")
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
        
        # Validation et échappement du contenu pour prévenir les attaques XSS
        if content.strip():
            # Échappement du HTML pour éviter les attaques XSS
            safe_content = html.escape(content)
            
            # Insertion du commentaire sécurisé
            db.execute(
                'INSERT INTO comments (product_id, user_id, content) VALUES (?, ?, ?)',
                (product_id, user_id, safe_content)
            )
            db.commit()
            
            logging.info(f"Nouveau commentaire par l'utilisateur {session['username']} sur le produit {product_id}")
            return redirect(url_for('product', product_id=product_id))
        else:
            flash('Le commentaire ne peut pas être vide.', 'error')
    
    # Transformation pour l'affichage sécurisé
    safe_comments = []
    for comment in comments:
        # Nous n'avons pas besoin d'échapper le contenu ici car il est déjà échappé lors de l'insertion
        # et le template n'utilise pas le filtre |safe
        safe_comments.append({
            'id': comment['id'],
            'content': comment['content'],
            'created_at': comment['created_at'],
            'username': comment['username']
        })
    
    return render_template('product.html', product=product, comments=safe_comments)

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
    app.run(debug=True, port=5001)  # Utilise un port différent pour la version sécurisée
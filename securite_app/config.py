import os

class Config:
    # Configuration générale
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'clé_très_secrète_pour_le_développement'
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    
    # Configuration de la base de données
    DATABASE = os.path.join(BASE_DIR, 'database.db')
    
    # Configuration de la sécurité
    SECURE_COOKIES = False  # Pour montrer la vulnérabilité XSS dans la version non sécurisée
    CSP_ENABLED = False  # Content Security Policy désactivé dans la version non sécurisée
    
    # Configuration de l'authentification
    MAX_LOGIN_ATTEMPTS = 3  # Pour la partie brute force
    LOGIN_TIMEOUT = 300  # 5 minutes de timeout après MAX_LOGIN_ATTEMPTS tentatives
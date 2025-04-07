import sqlite3
import os

# Chemin de la base de données
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database.db')

# Chemin du fichier schema.sql
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'schema.sql')

def init_db():
    """Initialise la base de données avec le schéma défini"""
    # Supprimer la base de données si elle existe
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    
    # Créer une nouvelle base de données
    conn = sqlite3.connect(DB_PATH)
    
    # Ouvrir et exécuter le fichier schema.sql
    with open(SCHEMA_PATH, 'r') as f:
        conn.executescript(f.read())
    
    conn.commit()
    conn.close()
    
    print(f"Base de données initialisée à {DB_PATH}")

if __name__ == "__main__":
    init_db()
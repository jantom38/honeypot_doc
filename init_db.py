from database_manager import DatabaseManager
import os
import logging

logging.basicConfig(level=logging.INFO)

def force_init():
    print("="*50)
    print("🛠️  RĘCZNA INICJALIZACJA BAZY DANYCH")
    print("="*50)

    if not os.path.exists('data'):
        os.makedirs('data')
        print("✅ Utworzono katalog 'data/'")

    db_path = os.path.join('data', 'honeypot_events.db')
    
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
            print(f"🗑️  Usunięto starą bazę: {db_path}")
        except Exception as e:
            print(f"❌ Nie można usunąć starej bazy (może jest otwarta?): {e}")
            return

    print(f"🔨 Tworzenie nowej bazy w: {db_path}...")
    try:
        db = DatabaseManager(db_path)
        
        conn = db._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
        if cursor.fetchone():
            print("✅ SUKCES! Tabela 'events' została utworzona.")
        else:
            print("❌ BŁĄD! Baza powstała, ale tabeli brak.")
        conn.close()
        
    except Exception as e:
        print(f"❌ BŁĄD KRYTYCZNY: {e}")

if __name__ == "__main__":
    force_init()

# Honeypot System

System typu Low-Interaction Honeypot służący do wykrywania intruzów, analizy zagrożeń (Threat Intelligence) oraz edukacji w zakresie cyberbezpieczeństwa. Projekt wykorzystuje konteneryzację Docker do bezpiecznej izolacji i łatwego wdrożenia.

## Funkcjonalności

System emuluje następujące usługi:
*   **SSH (Port 2222):** Rejestracja prób logowania (Brute Force).
*   **HTTP (Port 8080):** Wykrywanie skanowania paneli admina i SQL Injection.
*   **FTP (Port 2121):** Logowanie z blokadą transferu danych (ochrona przed malware).
*   **Telnet (Port 2323):** Pełna interakcja "Fake Shell" (symulacja Linuxa).
*   **SMTP (Port 2525):** Przechwytywanie treści spamu i phishingu.
*   **MySQL (Port 3306):** Rejestracja prób autoryzacji do bazy danych.

Dodatkowo system posiada:
*   **Dashboard (Streamlit):** Wizualizacja ataków w czasie rzeczywistym.
*   **Threat Intelligence:** Automatyczna klasyfikacja typów ataków.
*   **Skalowalność:** Możliwość uruchomienia wielu instancji honeypota.

## Wymagania

*   Docker Desktop (Windows/Mac) lub Docker Engine (Linux)
*   Docker Compose
*   Python 3.9+ (tylko do uruchamiania skryptów testowych lokalnie)

## Instalacja i Uruchomienie

1.  **Sklonuj repozytorium:**
    ```bash
    git clone <adres-repozytorium>
    cd honeypot_projekt
    ```

2.  **Uruchom system (Docker):**
    ```bash
    docker-compose up --build -d
    ```

3.  **Dostęp do Dashboardu:**
    Otwórz przeglądarkę i wejdź na adres: [http://localhost:8501](http://localhost:8501)

## Testowanie (Demo)

Aby wygenerować sztuczny ruch i przetestować działanie systemu, użyj dołączonego skryptu (wymaga Pythona na hoście):

```bash
pip install -r requirements.txt
python attacker.py
```

Możesz również użyć narzędzi takich jak **PuTTY** (Telnet/SSH) lub **FileZilla** (FTP), łącząc się na `localhost` i odpowiednie porty (np. 2121, 2323).

## Czyszczenie Środowiska (Reset)

Aby całkowicie usunąć system, zatrzymać kontenery i wyczyścić bazę danych, wykonaj następujące kroki:

1.  **Zatrzymaj i usuń kontenery:**
    ```bash
    docker-compose down
    ```

2.  **Usuń obrazy Docker (opcjonalnie):**
    ```bash
    docker rmi python_honeypot_primary python_honeypot_secondary honeypot_dashboard
    ```
    *(Nazwy obrazów mogą się różnić w zależności od nazwy katalogu projektu).*

3.  **Wyczyść wolumeny i dane:**
    Jeśli chcesz usunąć zebrane logi i zresetować bazę danych:
    ```bash
    # Linux / PowerShell
    rm -rf data/
    
    # CMD (Windows)
    rmdir /s /q data
    ```

4.  **Pełne czyszczenie Dockera (UWAGA: usuwa wszystkie nieużywane kontenery i wolumeny):**
    ```bash
    docker system prune -a --volumes
    ```

## Struktura Projektu

*   `main.py` - Główny serwer honeypota.
*   `connection_handler.py` - Logika obsługi poszczególnych protokołów (SSH, FTP, etc.).
*   `threat_intelligence.py` - Moduł analizy i klasyfikacji zagrożeń.
*   `database_manager.py` - Obsługa bazy danych SQLite.
*   `dashboard.py` - Kod interfejsu graficznego (Streamlit).
*   `attacker.py` - Skrypt do symulacji ataków.
*   `docker-compose.yml` - Konfiguracja środowiska Docker.

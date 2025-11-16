# IP Web Framework Scanner

Outil de scan IP permettant de détecter les frameworks web utilisés par les sites accessibles sur une plage d'adresses IP.

## 🇫🇷 Fonctionnalités
- Scan d’une plage d’IP
- Détection automatique de frameworks (WordPress, Laravel, Django, Symfony, Flask, etc.)
- Écriture des résultats dans des fichiers séparés
- Système de lock sécurisé pour l’écriture concurrente
- Log des scans

## 🇬🇧 Features
- IP range scanning
- Automatic detection of frameworks (WordPress, Laravel, Django, Symfony, Flask, etc.)
- Writes results to individual files
- Thread-safe file output using locks
- Logging system

## 📦 Installation
```
pip install requests filelock
```

## 🚀 Utilisation
```
python ipscan.py 192.168.1.1 192.168.1.255
```

ou

```
python ipscan.py
[+] IP start:
[+] IP end:
```

Les résultats seront enregistrés dans `results/`.

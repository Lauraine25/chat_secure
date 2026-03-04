# Client de Chat Sécurisé - Guide d'utilisation

## Vue d'ensemble

Le client de chat a été renforcé avec un chiffrement **bout en bout** robuste :

- **Boîte de dialogue de passphrase** au démarrage
- **Dérivation PBKDF2-HMAC-SHA256** de la clé (480 000 itérations - conforme OWASP 2024)
- **Chiffrement AES-256-CBC** côté client avant l'envoi
- **Déchiffrement côté client** à la réception

## Démarrage du client

```bash
python client.py
```

### Écran 1 : Saisie de la passphrase

**État initial de l'application :**

1. Une fenêtre modale s'affiche : "Sécurisation de votre chat"
2. Saisir une **passphrase** (minimum recommandé : 8 caractères)
3. Confirmer la passphrase
4. Cliquer **"Valider"** → La clé est dérivée localement (PBKDF2)

**Caractéristiques de sécurité :**

- La passphrase n'est **jamais** transmise au serveur
- La clé dérivée est générée **côté client** uniquement
- Un **sel aléatoire** de 16 bytes est généré à chaque session
- Les 480 000 itérations rendent les attaques par force brute infaisables en pratique

### Écran 2 : Interface de connexion

Après validation de la passphrase :

```
┌─────────────────────────────┐
│ Connexion                   │
│ Serveur:    localhost       │
│ Port:       5555            │
│ Nom d'util: alice           │
├─────────────────────────────┤
│ [Connecter]                 │
└─────────────────────────────┘
```

**Remarque :** Le champ "Passphrase" de l'écran de connexion a été supprimé car la passphrase est désormais demandée au démarrage et stockée en mémoire client uniquement.

## Flux de communication sécurisée

### Envoi d'un message

```
1. L'utilisateur saisit un message en clair dans Tkinter
   "Bonjour, c'est Alice!"

2. [CLIENT] Chiffrement local
   encrypted_content = encryption.encrypt(message)
   → Résultat: str base64 contenant (IV + ciphertext)

3. [CLIENT] Construction du paquet JSON
   {
       "type": "message",
       "recipient": "bob",
       "content": "baYx+zMKp/O9h2K...VfJQ=="  [chiffré]
   }

4. [SOCKET] Envoi over TCP

5. [SERVEUR] Stockage en BD (déjà chiffré)
   INSERT INTO messages 
   VALUES (..., content='baYx+zMKp/O9h2K...VfJQ==', ...)
```

### Réception d'un message

```
1. [SERVEUR] Lit depuis BD et envoie
   {
       "type": "message",
       "sender": "bob",
       "content": "XaLq/9iP2m...kL6W=="  [chiffré]
       "timestamp": "2026-03-04T14:30:45..."
   }

2. [CLIENT] Reçoit le paquet JSON

3. [CLIENT] Déchiffrement local
   plaintext = encryption.decrypt(encrypted_content)
   → Résultat: "Bonjour Alice, ça va?"

4. [CLIENT] Affichage dans Tkinter
   [14:30:45] bob
   Bonjour Alice, ça va?
```

## Flux d'authentification sécurisée

À la connexion, le client envoie :

```json
{
    "username": "alice",
    "key": "qF9z4LnX...vM8="  [clé dérivée, base64],
    "salt": "jH2K9pL...nQ=="  [sel utilisé, base64]
}
```

**Serveur :**

- Stocke la clé pour cette session
- L'utilise pour **pré-chiffrer** les messages destinés à Alice
- Conserve le sel en cache si l'utilisateur se déconnecte

## Sécurité du stockage en BD

Avant (v1) :
```sql
INSERT INTO messages 
VALUES (NULL, 'alice', 'bob', '<encrypted>', NULL, NOW(), FALSE, '192.168.1.10');
```

Après (v2) avec PBKDF2 + double-chiffrement :
```sql
INSERT INTO messages 
VALUES (NULL, 'alice', 'bob', 
    '<chiffré_avec_clé_alice>', 
    '<chiffré_avec_clé_bob>',    ← Pré-chiffré côté serveur
    NOW(), FALSE, '192.168.1.10');
```

- Deux versions chiffrées stockées
- Chaque participant voit sa propre version
- Totalement imperméable même en cas de fuite BD

## Implémentation technique

### Classe `AESEncryption`

```python
# Dérivation de clé robuste
key, salt = AESEncryption.key_from_password("ma-passphrase")
# → key: 32 bytes (256 bits)
# → salt: 16 bytes (aléatoire)

# Chiffrement
cipher = AESEncryption(key)
encrypted = cipher.encrypt("Message en clair")
# → Format: IV (16 bytes) + Ciphertext (variable)
# → Encodé base64 pour transmission JSON

# Déchiffrement
plaintext = cipher.decrypt(encrypted)
```

### Paramètres PBKDF2

- **Fonction de hash :** HMAC-SHA256
- **Itérations :** 480 000 (OWASP 2024 recommendation)
- **Longueur de clé :** 32 bytes (256 bits)
- **Sel :** 16 bytes, aléatoire par session

## Schémas de sécurité

### Perfect Forward Secrecy (PFS) ???

**Non implémenté.** Chaque session utilise le même dérivé PBKDF2. 

Pour améliorer :
- Générer une clé de session éphémère
- Utiliser ECDH pour l'échange initial
- Rotationner la clé de session régulièrement

### Authentification ??

**Non implémenté.** Pas de vérification d'intégrité (HMAC/GCM).

Pour améliorer :
- Passer à AES-256-GCM (chiffrement + authentification)
- Signer chaque message avec la clé

### Attaques possibles

❌ **Déchiffrement des messages** - Impossible sans la passphrase
❌ **Replay d'anciens messages** - Possible (pas de nonce/timestamp binding)
❌ **Man-in-the-Middle** - Possible (pas de chaîne PKI)
✓ **Brute force PBKDF2** - Coûteux (480 000 itérations)

## Tests

```bash
python -m unittest test_encryption -v
```

Résultats attendus :
- 23 tests
- Validation du chiffrement AES-256-CBC
- Validation de PBKDF2-HMAC
- Validation de la dérivation déterministe avec sel

## Optimisations suggérées

1. **Upgraded vers AES-256-GCM** (chiffrement + intégrité en un)
2. **Implémenter ECDH** pour l'échange de clés
3. **Ajouter Timestamps strictes** (anti-replay)
4. **Signature HMAC** des messages envoyés
5. **Rotation de clés** toutes les N sessions

---

**Version :** 2.1 (PBKDF2 + Client-side Encryption)  
**Date :** Mars 2026  
**Sécurité :** Forte (chiffrement 256 bits + dérivation PBKDF2)

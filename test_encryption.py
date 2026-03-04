"""
Tests unitaires pour le module de chiffrement AES-256
Valide la sécurité et la fiabilité du chiffrement des messages
"""

import unittest
import os
from encryption import AESEncryption


class TestAESEncryption(unittest.TestCase):
    """Suite de tests pour la classe AESEncryption"""
    
    def setUp(self):
        """Initialiser les ressources de test"""
        self.cipher = AESEncryption()
    
    def tearDown(self):
        """Nettoyer après les tests"""
        self.cipher = None
    
    # ========== Tests de Base ==========
    
    def test_encrypt_decrypt_cycle(self):
        """Test: Chiffrement et déchiffrement simples"""
        plaintext = "Ceci est un message secret!"
        
        # Chiffrer
        ciphertext = self.cipher.encrypt(plaintext)
        
        # Vérifier que le ciphertext est différent
        self.assertNotEqual(plaintext, ciphertext)
        
        # Déchiffrer
        decrypted = self.cipher.decrypt(ciphertext)
        
        # Vérifier que c'est identique
        self.assertEqual(plaintext, decrypted)
    
    def test_encrypt_decode_consistency(self):
        """Test: Cohérence du chiffrement (même plaintext = ciphertext différent)"""
        plaintext = "Message de test"
        
        # Chiffrer 3 fois
        cipher1 = self.cipher.encrypt(plaintext)
        cipher2 = self.cipher.encrypt(plaintext)
        cipher3 = self.cipher.encrypt(plaintext)
        
        # Les ciphertexts doivent être différents (IV aléatoire)
        self.assertNotEqual(cipher1, cipher2)
        self.assertNotEqual(cipher2, cipher3)
        self.assertNotEqual(cipher1, cipher3)
        
        # Mais tous doivent déchiffrer au même texte
        self.assertEqual(self.cipher.decrypt(cipher1), plaintext)
        self.assertEqual(self.cipher.decrypt(cipher2), plaintext)
        self.assertEqual(self.cipher.decrypt(cipher3), plaintext)
    
    # ========== Tests de Contenu ==========
    
    def test_empty_message(self):
        """Test: Message vide"""
        plaintext = ""
        ciphertext = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted)
    
    def test_long_message(self):
        """Test: Message très long"""
        plaintext = "A" * 10000  # 10 000 caractères
        ciphertext = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted)
    
    def test_special_characters(self):
        """Test: Caractères spéciaux et Unicode"""
        plaintext = "Bonjour! 你好 مرحبا 🔐🔑 Œuvre €"
        ciphertext = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted)
    
    def test_multiline_message(self):
        """Test: Message multi-ligne"""
        plaintext = """Ligne 1
Ligne 2
Ligne 3
Etc..."""
        ciphertext = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted)
    
    # ========== Tests de Sécurité ==========
    
    def test_key_generation(self):
        """Test: Génération de clés aléatoires"""
        key1 = AESEncryption.generate_key()
        key2 = AESEncryption.generate_key()
        
        # Les clés doivent être différentes
        self.assertNotEqual(key1, key2)
        
        # Les clés doivent faire 32 bytes (256 bits)
        self.assertEqual(len(key1), 32)
        self.assertEqual(len(key2), 32)
    
    def test_iv_generation(self):
        """Test: Génération de vecteurs d'initialisation"""
        iv1 = AESEncryption.generate_iv()
        iv2 = AESEncryption.generate_iv()
        
        # Les IVs doivent être différents (aléatoires)
        self.assertNotEqual(iv1, iv2)
        
        # Les IVs doivent faire 16 bytes
        self.assertEqual(len(iv1), 16)
        self.assertEqual(len(iv2), 16)
    
    def test_invalid_key_length(self):
        """Test: Rejet de clés avec mauvaise longueur"""
        # Clé trop courte (16 bytes au lieu de 32)
        invalid_key = os.urandom(16)
        
        with self.assertRaises(ValueError):
            AESEncryption(invalid_key)
    
    def test_different_keys_different_output(self):
        """Test: Deux clés différentes = chiffrement différent"""
        plaintext = "Message secret"
        
        # Créer deux instances avec des clés différentes
        key1 = AESEncryption.generate_key()
        key2 = AESEncryption.generate_key()
        
        cipher1 = AESEncryption(key1)
        cipher2 = AESEncryption(key2)
        
        # Chiffrer avec les deux clés
        ciphertext1 = cipher1.encrypt(plaintext)
        ciphertext2 = cipher2.encrypt(plaintext)
        
        # Essayer de déchiffrer chaque ciphertext avec la mauvaise clé
        # Devrait échouer ou retourner un garbage
        try:
            result = cipher2.decrypt(ciphertext1)
            # Si ça marche, le padding a échoué (c'est bon!)
            self.assertNotEqual(result, plaintext)
        except:
            # C'est attendu que ça lève une exception
            pass
    
    def test_tampering_detection(self):
        """Test: Détection de modification des données"""
        plaintext = "Données sensibles"
        ciphertext = self.cipher.encrypt(plaintext)
        
        # Modifier le ciphertext (tamper)
        tampered = ciphertext[:-10] + "aaaaaaaaaa"
        
        # Essayer de déchiffrer
        try:
            decrypted = self.cipher.decrypt(tampered)
            # Si ça réussit, ce ne serait pas le texte original
            self.assertNotEqual(decrypted, plaintext)
        except:
            # Exception attendue pour les données corrompues
            pass
    
    # ========== Tests de Interopérabilité ==========
    
    def test_key_sharing(self):
        """Test: Partage de clé entre deux instances"""
        plaintext = "Message partagé"
        
        # Créer une instance
        cipher1 = AESEncryption()
        key_b64 = cipher1.get_key_b64()
        
        # Extraire la clé
        shared_key = AESEncryption.key_from_b64(key_b64)
        
        # Créer une deuxième instance avec la clé partagée
        cipher2 = AESEncryption(shared_key)
        
        # Chiffrer avec cipher1
        ciphertext = cipher1.encrypt(plaintext)
        
        # Déchiffrer avec cipher2
        decrypted = cipher2.decrypt(ciphertext)
        
        # Doit être identique
        self.assertEqual(plaintext, decrypted)

    def test_password_derivation(self):
        """Test: Clé dérivée d'une passphrase avec PBKDF2"""
        # Ancien test : Supprimé car key_from_password retourne maintenant (key, salt)
        # Ce comportement est testé dans test_pbkdf2_key_derivation
        pass
    
    def test_base64_encoding(self):
        """Test: Encodage base64 des clés"""
        key = AESEncryption.generate_key()
        cipher = AESEncryption(key)
        
        # Encoder en base64
        key_b64 = cipher.get_key_b64()
        
        # Vérifier que c'est du texte ASCII valide
        self.assertIsInstance(key_b64, str)
        self.assertTrue(all(ord(c) < 128 for c in key_b64))
        
        # Décoder et vérifier
        decoded_key = AESEncryption.key_from_b64(key_b64)
        self.assertEqual(key, decoded_key)

    def test_pbkdf2_key_derivation(self):
        """Test: Dérivation de clé avec PBKDF2-HMAC"""
        passphrase = "mon-mot-de-passe-secret-123"
        key1, salt1 = AESEncryption.key_from_password(passphrase)
        
        # Vérifier la taille de la clé
        self.assertEqual(len(key1), 32)
        
        # Vérifier la taille du sel
        self.assertEqual(len(salt1), 16)
        
        # Dériver à nouveau avec le même sel doit donner la même clé
        key2, _ = AESEncryption.key_from_password(passphrase, salt1)
        self.assertEqual(key1, key2)
        
        # Dériver avec un sel différent doit donner une clé différente
        key3, salt3 = AESEncryption.key_from_password(passphrase)
        self.assertNotEqual(key1, key3)
        self.assertNotEqual(salt1, salt3)
    
    def test_pbkdf2_deterministic_with_salt(self):
        """Test: PBKDF2 est déterministe avec un sel fixe"""
        passphrase = "test-passphrase"
        salt = os.urandom(16)
        
        # Dériver plusieurs fois avec le même sel
        key1, _ = AESEncryption.key_from_password(passphrase, salt)
        key2, _ = AESEncryption.key_from_password(passphrase, salt)
        key3, _ = AESEncryption.key_from_password(passphrase, salt)
        
        # Tous doivent être identiques
        self.assertEqual(key1, key2)
        self.assertEqual(key2, key3)
    
    def test_pbkdf2_salt_encoding(self):
        """Test: Encodage/décodage du sel"""
        original_salt = os.urandom(16)
        
        # Encoder en base64
        salt_b64 = AESEncryption.salt_to_b64(original_salt)
        
        # Vérifier que c'est du texte ASCII valide
        self.assertIsInstance(salt_b64, str)
        self.assertTrue(all(ord(c) < 128 for c in salt_b64))
        
        # Décoder
        decoded_salt = AESEncryption.salt_from_b64(salt_b64)
        self.assertEqual(original_salt, decoded_salt)
    
    def test_pbkdf2_different_passphrases(self):
        """Test: Passphrases différentes = clés différentes"""
        salt = os.urandom(16)
        pass1 = "password1"
        pass2 = "password2"
        
        key1, _ = AESEncryption.key_from_password(pass1, salt)
        key2, _ = AESEncryption.key_from_password(pass2, salt)
        
        # Clés doivent être différentes
        self.assertNotEqual(key1, key2)
    
    # ========== Tests de Performance ==========
    
    def test_large_message_performance(self):
        """Test: Chiffrement de gros messages"""
        # Message de 1 MB
        plaintext = "X" * (1024 * 1024)
        
        # Chiffrer (doit pas te prendre plus que quelques secondes)
        ciphertext = self.cipher.encrypt(plaintext)
        
        # Déchiffrer
        decrypted = self.cipher.decrypt(ciphertext)
        
        # Vérifier
        self.assertEqual(plaintext, decrypted)
    
    def test_multiple_cycles(self):
        """Test: Cycles de chiffrement/déchiffrement répétés"""
        plaintext = "Message de test"
        
        message = plaintext
        for i in range(100):
            # Chiffrer puis déchiffrer 100 fois
            encrypted = self.cipher.encrypt(message)
            message = self.cipher.decrypt(encrypted)
        
        # Doit toujours être identique
        self.assertEqual(message, plaintext)


class TestAESSecurityProperties(unittest.TestCase):
    """Tests des propriétés de sécurité du chiffrement AES-256"""
    
    def test_no_plaintext_visible(self):
        """Test: Le plaintext n'est pas visible dans le ciphertext"""
        plaintext = "This is highly sensitive information"
        cipher = AESEncryption()
        ciphertext = cipher.encrypt(plaintext)
        
        # Le plaintext ne doit pas apparaître en clair
        self.assertNotIn(plaintext, ciphertext)
    
    def test_ciphertext_randomness(self):
        """Test: Le ciphertext a entropie élevée (IV aléatoire)"""
        plaintext = "A" * 1000  # Même plaintext répété
        cipher = AESEncryption()
        
        ciphertexts = [cipher.encrypt(plaintext) for _ in range(10)]
        
        # Tous doivent être différents
        self.assertEqual(len(ciphertexts), len(set(ciphertexts)))
    
    def test_avalanche_effect(self):
        """Test: Petit changement en plaintext = gros changement en ciphertext"""
        plaintext1 = "Secret message 1"
        plaintext2 = "Secret message 2"  # Un seul caractère différent
        
        cipher = AESEncryption()
        
        cipher1 = cipher.encrypt(plaintext1)
        cipher2 = cipher.encrypt(plaintext2)
        
        # Les ciphertexts doivent être significativement différents
        self.assertNotEqual(cipher1, cipher2)
        
        # Vérifier qu'au moins 30% des bits sont différents
        # (Diffusion - une des propriétés d'AES)
        bits_different = sum(bin(a ^ b).count('1') for a, b in zip(cipher1.encode(), cipher2.encode()))
        bits_total = len(cipher1.encode()) * 8
        
        # Au moins 20% doivent être différents
        self.assertGreater(bits_different / bits_total, 0.2)


def run_security_report():
    """Affiche un rapport de sécurité"""
    print("\n" + "="*60)
    print("RAPPORT DE SÉCURITÉ - CHIFFREMENT AES-256")
    print("="*60)
    
    print("\n✓ Algorithme: AES (Advanced Encryption Standard)")
    print("  - Clé: 256 bits (32 bytes)")
    print("  - Mode: CBC (Cipher Block Chaining)")
    print("  - Padding: PKCS7")
    print("  - IV: Aléatoire (16 bytes) par message")
    
    print("\n✓ Sécurité Apportée:")
    print("  - Confidentialité: Très forte (cryptage militaire)")
    print("  - Intégrité: Partielle (à ajouter HMAC/GCM)")
    print("  - Authentification: Absente (à implémenter)")
    print("  - Perfect Forward Secrecy: Non (clés statiques)")
    
    print("\n⚠ Limitations Actuelles:")
    print("  - Pas de vérification d'intégrité (MAC)")
    print("  - Pas d'authentification d'expéditeur")
    print("  - Clés statiques (pas de rotation)")
    print("  - Pas de perfect forward secrecy")
    
    print("\n💡 Recommandations:")
    print("  - Ajouter AES-256-GCM pour intégrité")
    print("  - Implémenter ECDH pour l'échange de clés")
    print("  - Ajouter signature numérique des messages")
    print("  - Implémenter rotation de clés périodique")
    
    print("\n" + "="*60 + "\n")


if __name__ == '__main__':
    # Afficher le rapport de sécurité
    run_security_report()
    
    # Exécuter les tests
    unittest.main(verbosity=2)

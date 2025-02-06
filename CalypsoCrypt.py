#!pip install pycryptodome cryptography (Colab)  ou  pip install pycryptodome cryptography

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import time

# Fonction pour générer une clé RSA
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Fonction pour chiffrer un message avec AES
def encrypt_message_aes(key, plaintext):
    iv = os.urandom(16)  # Initialisation Vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Ajouter un padding au plaintext
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

# Fonction pour déchiffrer un message avec AES
def decrypt_message_aes(key, ciphertext):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()

    # Retirer le padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

# Fonction pour chiffrer la clé AES avec RSA
def encrypt_key_rsa(public_key, aes_key):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return encrypted_key

# Fonction pour déchiffrer la clé AES avec RSA
def decrypt_key_rsa(private_key, encrypted_key):
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)
    return aes_key

# Fonction pour envoyer un message sécurisé
def send_secure_message(public_key, plaintext):
    # 1. Générer une clé AES
    aes_key = os.urandom(32)  # Clé AES 256 bits

    # 2. Chiffrer le message avec AES
    encrypted_message = encrypt_message_aes(aes_key, plaintext)

    # 3. Chiffrer la clé AES avec la clé publique RSA
    encrypted_key = encrypt_key_rsa(public_key, aes_key)

    return encrypted_key, encrypted_message

# Fonction pour recevoir et déchiffrer un message sécurisé
def receive_secure_message(private_key, encrypted_key, encrypted_message):
    # 1. Déchiffrer la clé AES avec la clé privée RSA
    aes_key = decrypt_key_rsa(private_key, encrypted_key)

    # 2. Déchiffrer le message avec la clé AES
    decrypted_message = decrypt_message_aes(aes_key, encrypted_message)

    return decrypted_message

# Fonction pour supprimer les données sensibles
def delete_sensitive_data():
    global encrypted_key, encrypted_message
    encrypted_key = None
    encrypted_message = None
    print("Les données sensibles ont été supprimées en raison d'une tentative de mot de passe incorrect.")

# Fonction pour vérifier le mot de passe
def verify_password(password, correct_password):
    return password == correct_password


correct_password = input("Définissez un mot de passe : ")
attempt_time = 240  # Temps initial d'attente en secondes
tentatives = 10

# Générer les paires de clés RSA
private_key, public_key = generate_rsa_key_pair()
print("Voici la private key:\n", private_key.decode())

# Envoyer un message sécurisé
message =input("Message secret sécurisé avec cryptage hybride à tester ")
encrypted_key, encrypted_message = send_secure_message(public_key, message)
print(f"Message chiffré : {encrypted_message}")

# Demander le mot de passe à l'utilisateur
user_password = input("Entrez le mot de passe : ")

# Vérifier le mot de passe
if verify_password(user_password, correct_password):
    # Si le mot de passe est correct, déchiffrer le message
    decrypted_message = receive_secure_message(private_key, encrypted_key, encrypted_message)
    print(f"Message déchiffré : {decrypted_message}")
else:
    # Si le mot de passe est incorrect
    while tentatives > 0:
        if verify_password(user_password, correct_password):
            # Si le mot de passe est correct, déchiffrer le message
            decrypted_message = receive_secure_message(private_key, encrypted_key, encrypted_message)
            print(f"Message déchiffré : {decrypted_message}")
            break
        else:
            tentatives -= 1
            if tentatives == 0:
                delete_sensitive_data()
                break
            print(f"Mot de passe incorrect. Veuillez réessayer dans {attempt_time/60} minutes  .")
            print(f"Il vous reste {tentatives} tentatives avant que les données soient supprimées.")
            time.sleep(attempt_time)
            attempt_time *= 8  # Multiplier le temps d'attente par...
            user_password = input("Entrez le mot de passe : ")
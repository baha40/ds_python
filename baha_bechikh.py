import re
import hashlib
import bcrypt
import rsa

# Dictionnaire de mots de passe courants pour les attaques par dictionnaire
mots_de_passe_communs = ["password", "123456", "qwerty", "admin", "welcome", "secret"]

# Fonction pour enregistrer un utilisateur
def enregistrer_utilisateur():
    email = input("Entrez votre e-mail : ")
    mot_de_passe = input("Entrez un mot de passe (8 caractères minimum, avec majuscule, minuscule, chiffre, et caractère spécial) : ")

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        print("Format d'e-mail invalide")
        return

    if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$!])[A-Za-z\d@#$!]{8,}$", mot_de_passe):
        print("Format de mot de passe invalide")
        return

    with open("Enregistrement.txt", "a") as f:
        f.write(f"{email}:{hashlib.sha256(mot_de_passe.encode()).hexdigest()}\n")
    print("Enregistrement réussi")

# Fonction pour authentifier un utilisateur
def authentifier_utilisateur():
    email = input("Entrez votre adresse e-mail : ")
    mot_de_passe = input("Entrez votre mot de passe : ")

    with open("Enregistrement.txt", "r") as f:
        for line in f:
            email_stocke, mot_de_passe_stocke = line.strip().split(":")
            if email == email_stocke and hashlib.sha256(mot_de_passe.encode()).hexdigest() == mot_de_passe_stocke:
                print("Authentification réussie")
                afficher_menu()
                return

    print("Authentification échouée. Veuillez vous enregistrer.")

# Fonction pour afficher le menu principal après authentification
def afficher_menu():
    while True:
        print("\nMenu Principal :")
        print("A- Hacher un mot (invisible)")
        print("B- Chiffrement (RSA)")
        print("C- Certificat (RSA)")
        print("D- Quitter")

        choix = input("Sélectionnez une option (A/B/C/D) : ")

        if choix == 'A':
            menu_hachage()
        elif choix == 'B':
            menu_chiffrement_rsa()
        elif choix == 'C':
            menu_certificat_rsa()
        elif choix == 'D':
            print("Au revoir!")
            break
        else:
            print("Option invalide. Veuillez réessayer.")

# Fonction pour effectuer une attaque par dictionnaire
def attaque_par_dictionnaire():
    hachage_cible = input("Entrez le hachage à attaquer : ")
    
    for mot in mots_de_passe_communs:
        hachage_mot = hashlib.sha256(mot.encode()).hexdigest()
        if hachage_mot == hachage_cible:
            print(f"Mot de passe trouvé : {mot}")
            return

    print("Attaque par dictionnaire échouée. Mot de passe non trouvé.")

# Menu pour les options de hachage
def menu_hachage():
    while True:
        print("\nMenu de Hachage :")
        print("a- Hacher le mot par SHA-256")
        print("b- Hacher le mot en générant un sel (bcrypt)")
        print("c- Attaquer par dictionnaire le mot inséré")
        print("d- Revenir au menu principal")

        choix = input("Sélectionnez une option (a/b/c/d) : ")

        if choix == 'a':
            mot = input("Entrez un mot à hacher : ")
            hachage_mot = hashlib.sha256(mot.encode()).hexdigest()
            print(f"Hachage SHA-256 : {hachage_mot}")
        elif choix == 'b':
            mot = input("Entrez un mot à hacher avec un sel : ")
            sel = bcrypt.gensalt()
            hachage_mot = bcrypt.hashpw(mot.encode(), sel)
            print(f"Hachage bcrypt : {hachage_mot}")
        elif choix == 'c':
            attaque_par_dictionnaire()
        elif choix == 'd':
            return
        else:
            print("Option invalide. Veuillez réessayer.")

# Fonction pour les options de chiffrement RSA
def menu_chiffrement_rsa():
    while True:
        print("\nMenu de Chiffrement RSA :")
        print("a- Générer les paires de clés dans un fichier")
        print("b- Chiffrer un message de votre choix par RSA")
        print("c- Déchiffrer un message chiffré par RSA")
        print("d- Signer un message de votre choix par RSA")
        print("e- Vérifier la signature du message signé")
        print("f- Revenir au menu principal")

        choix = input("Sélectionnez une option (a/b/c/d/e/f) : ")

        if choix == 'a':
            # Générer les paires de clés RSA et les enregistrer dans un fichier
            (cle_publique, cle_privee) = rsa.newkeys(512)
            with open("cle_rsa.txt", "w") as f:
                f.write(f"Cle publique : {cle_publique.save_pkcs1().decode()}\n")
                f.write(f"Cle privee : {cle_privee.save_pkcs1().decode()}\n")
            print("Paires de cles RSA generees et enregistrees dans cle_rsa.txt")
        elif choix == 'b':
            message = input("Entrez le message à chiffrer : ")
            with open("cle_rsa.txt", "r") as f:
                lignes = f.readlines()
                cle_publique_str = lignes[0].split(":")[1].strip()
                cle_publique = rsa.PublicKey.load_pkcs1(cle_publique_str.encode())
            message_chiffre = rsa.encrypt(message.encode(), cle_publique)
            print(f"Message chiffre : {message_chiffre}")
        elif choix == 'c':
            message_chiffre = input("Entrez le message chiffre : ")
            with open("cle_rsa.txt", "r") as f:
                lignes = f.readlines()
                cle_privee_str = lignes[1].split(":")[1].strip()
                cle_privee = rsa.PrivateKey.load_pkcs1(cle_privee_str.encode())
            message_dechiffre = rsa.decrypt(message_chiffre.encode(), cle_privee)
            print(f"Message dechiffre : {message_dechiffre.decode()}")
        elif choix == 'd':
            message = input("Entrez le message à signer : ")
            with open("cle_rsa.txt", "r") as f:
                lignes = f.readlines()
                cle_privee_str = lignes[1].split(":")[1].strip()
                cle_privee = rsa.PrivateKey.load_pkcs1(cle_privee_str.encode())
            signature = rsa.sign(message.encode(), cle_privee, 'SHA-1')
            print(f"Signature du message : {signature}")
        elif choix == 'e':
            message = input("Entrez le message : ")
            signature = input("Entrez la signature du message : ")
            with open("cle_rsa.txt", "r") as f:
                lignes = f.readlines()
                cle_publique_str = lignes[0].split(":")[1].strip()
                cle_publique = rsa.PublicKey.load_pkcs1(cle_publique_str.encode())
            if rsa.verify(message.encode(), signature, cle_publique):
                print("La signature est valide.")
            else:
                print("La signature n'est pas valide.")
        elif choix == 'f':
            return
        else:
            print("Option invalide. Veuillez réessayer.")

# Fonction pour les options de certificat RSA
def menu_certificat_rsa():
    while True:
        print("\nMenu de Certificat RSA :")
        print("a- Générer les paires de clés dans un fichier")
        print("b- Générer un certificat autosigné par RSA")
        print("c- Chiffrer un message de votre choix par ce certificat")
        print("d- Revenir au menu principal")

        choix = input("Sélectionnez une option (a/b/c/d) : ")

        if choix == 'a':
            # Générer les paires de clés RSA et les enregistrer dans un fichier
            (cle_publique, cle_privee) = rsa.newkeys(512)
            with open("cle_rsa_certificat.txt", "w") as f:
                f.write(f"Cle publique : {cle_publique.save_pkcs1().decode()}\n")
                f.write(f"Cle privee : {cle_privee.save_pkcs1().decode()}\n")
            print("Paires de cles RSA generees et enregistrees dans cle_rsa_certificat.txt")
        elif choix == 'b':
            with open("cle_rsa_certificat.txt", "r") as f:
                lignes = f.readlines()
                cle_privee_str = lignes[1].split(":")[1].strip()
                cle_privee = rsa.PrivateKey.load_pkcs1(cle_privee_str.encode())
            certificat = rsa.sign("Certificat".encode(), cle_privee, 'SHA-1')
            print(f"Certificat autosigne genere : {certificat}")
        elif choix == 'c':
            message = input("Entrez le message à chiffrer avec le certificat : ")
            with open("cle_rsa_certificat.txt", "r") as f:
                lignes = f.readlines()
                cle_publique_str = lignes[0].split(":")[1].strip()
                cle_publique = rsa.PublicKey.load_pkcs1(cle_publique_str.encode())
            message_chiffre = rsa.encrypt(message.encode(), cle_publique)
            print(f"Message chiffre avec le certificat : {message_chiffre}")
        elif choix == 'd':
            return
        else:
            print("Option invalide. Veuillez réessayer.")

if __name__ == "__main__":
    while True:
        print("\nBienvenue dans l'application!")
        print("1- S'enregistrer")
        print("2- S'authentifier")
        print("3- Quitter")

        choix = input("Sélectionnez une option (1/2/3) : ")

        if choix == '1':
            enregistrer_utilisateur()
        elif choix == '2':
            authentifier_utilisateur()
        elif choix == '3':
            print("Au revoir!")
            break
        else:
            print("Option invalide")

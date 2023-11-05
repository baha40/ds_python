import re
import hashlib
import bcrypt
import rsa

# Enregistrement utilisateur
def enregistrer():
    email = input("e-mail : ")
    password = input("Mot de passe : ")

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        print("E-mail invalide")
        return

    if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$!])[A-Za-z\d@#$!]{8,}$", password):
        print("Mot de passe non sécurisé")
        return

    with open("Enregistrement.txt", "a") as f:
        f.write(f"{email}:{hashlib.sha256(password.encode()).hexdigest()}\n")

# Authentification utilisateur
def authentifier():
    email = input("e-mail : ")
    password = input("Mot de passe : ")

    with open("Enregistrement.txt", "r") as f:
        for line in f:
            stored_email, stored_password = line.strip().split(":")
            if email == stored_email and hashlib.sha256(password.encode()).hexdigest() == stored_password:
                print("Authentification réussie")
                menu_principal()
                return

    print("Authentification échouée. Veuillez vous enregistrer.")
    enregistrer()

# Menu principal
def menu_principal():
    while True:
        print("Menu Principal :")
        print("A- Hacher un mot")
        print("B- Chiffrement RSA")
        print("C- Certificat RSA")
        choix = input("Choix (A/B/C) : ")

        if choix == 'A':
            menu_hachage()
        elif choix == 'B':
            menu_chiffrement_rsa()
        elif choix == 'C':
            menu_certificat_rsa()
        else:
            print("Choix invalide. Réessayez.")

# Menu de hachage
def menu_hachage():
    while True:
        print("Menu de Hachage :")
        print("a- Hacher avec SHA-256")
        print("b- Hacher avec bcrypt")
        print("c- Attaque par dictionnaire")
        print("d- Retour au menu principal")
        choix = input("Choix (a/b/c/d) : ")

        if choix == 'a':
            mot = input("Mot à hacher : ")
            mot_hache = hashlib.sha256(mot.encode()).hexdigest()
            print(f"Hachage SHA-256 : {mot_hache}")
        elif choix == 'b':
            mot = input("Mot à hacher avec un sel : ")
            sel = bcrypt.gensalt()
            mot_hache = bcrypt.hashpw(mot.encode(), sel)
            print(f"Hachage bcrypt : {mot_hache}")
        elif choix == 'c':
            print("Attaque par dictionnaire non implémentée.")
        elif choix == 'd':
            return
        else:
            print("Choix invalide. Réessayez.")

# Menu de chiffrement RSA
def menu_chiffrement_rsa():
    print("Menu de Chiffrement RSA :")
 

# Menu de certificat RSA
def menu_certificat_rsa():
    print("Menu de Certificat RSA :")


if __name__ == "__main__":
    while True:
        print("1- S'enregistrer")
        print("2- S'authentifier")
        print("3- Quitter")
        choix = input("Choix (1/2/3) : ")

        if choix == '1':
            enregistrer()
        elif choix == '2':
            authentifier()
        elif choix == '3':
            print("Au revoir!")
            break
        else:
            print("Choix invalide. Réessayez.")

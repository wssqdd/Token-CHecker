import requests
from pystyle import Colorate, Colors
from colorama import Fore, Style

def check_token_nitro(token):
    url = "https://discord.com/api/v9/users/@me"
    headers = {
        "Authorization": token,
        "User-Agent": "Mozilla/5.0"
    }
    try:
        response = requests.get(url, headers=headers)
    except Exception as e:
        print(f"Erreur de connexion pour le token {token[:10]}...: {e}")
        return

    if response.status_code == 200:
        data = response.json()
        username = f"{data['username']}#{data['discriminator']}"
        premium_type = data.get('premium_type', 0)
        if premium_type == 0:
            print(f"{Fore.RED}[-] Token invalide {token[:10]}")
        else:
            print(f"{Fore.GREEN}[+] Token valide {token[:10]} - Utilisateur: {username}")
    elif response.status_code == 401:
        print(f"{Fore.RED}[-] Token invalide {token[:10]}")
    else:
        print(f"Erreur API {response.status_code} pour le token {token[:10]}...")
    
    
def close():
    exit()

def start_scan():
    try:
        with open("tokens.txt", "r") as f:
            tokens = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("Fichier tokens.txt introuvable !")
        return

    print(Colorate.Vertical(Colors.blue_to_green, f"Lancement du scan pour {len(tokens)} tokens\n"))
    for token in tokens:
        check_token_nitro(token)

text = """
████████╗ █████╗ ██╗  ██╗███████╗███╗  ██╗   █████╗ ██╗  ██╗███████╗ █████╗ ██╗  ██╗███████╗██████╗ 
╚══██╔══╝██╔══██╗██║ ██╔╝██╔════╝████╗ ██║  ██╔══██╗██║  ██║██╔════╝██╔══██╗██║ ██╔╝██╔════╝██╔══██╗
   ██║   ██║  ██║█████═╝ █████╗  ██╔██╗██║  ██║  ╚═╝███████║█████╗  ██║  ╚═╝█████═╝ █████╗  ██████╔╝
   ██║   ██║  ██║██╔═██╗ ██╔══╝  ██║╚████║  ██║  ██╗██╔══██║██╔══╝  ██║  ██╗██╔═██╗ ██╔══╝  ██╔══██╗
   ██║   ╚█████╔╝██║ ╚██╗███████╗██║ ╚███║  ╚█████╔╝██║  ██║███████╗╚█████╔╝██║ ╚██╗███████╗██║  ██║
   ╚═╝    ╚════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚══╝   ╚════╝ ╚═╝  ╚═╝╚══════╝ ╚════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

    [1] - Lancer le scan des tokens
    [2] - Quitter
   
"""

def menu():
    while True:
        
        print(Colorate.Vertical(Colors.blue_to_green, text))
        choice = input(Colorate.Vertical(Colors.blue_to_green, "Entrez votre choix : "))

        if choice == "1":
            start_scan()
            print(Colorate.Vertical(Colors"Scan terminé.")
            close()
            break
        elif choice == "2":
            print("Au revoir !")
            break
        else:
            print("Choix invalide, veuillez réessayer.")

if __name__ == "__main__":
    menu()

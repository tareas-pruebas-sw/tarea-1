import random

def generatePassword(passwordLength: int, listaCaracteres: list) -> str:
    password = []
    random.shuffle(listaCaracteres)
    for i in range(passwordLength):
        randomchar = random.choice(listaCaracteres)
        password.append(randomchar)
    return "".join(password)
import string
import logging
import hashlib

from punctuation import punctuation
from mongo import get_user_collection
from password_generator import generatePassword
from password_manager import PasswordManager
from cryptography.fernet import Fernet

logging.basicConfig(filename='mypass.log', level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    # Get the user collection
    try:
        user_collection = get_user_collection()
    except Exception as e:
        print(e)
        return
    
    print("1. Login")
    print("2. Register")
    print("3. Password generator")
    print("4. Exit")
    choice = input("Enter your choice: ")

    if choice == "1":
        logger.info("User in login")

        while True:
            username = input("Enter your username: ")
            password = input("Enter your password: ")

            try:
                user = user_collection.find_one({"username": username})
            except Exception as e:
                print(e)
                logger.error(f"Captured error: {e}")
                return

            if user and user.get("password") == hashlib.sha256(password.encode()).hexdigest():
                logger.info("User logged in")
                break
            else:
                logger.error("User error: invalid credentials")
                print("Invalid credentials")
        
    elif choice == "2":
        logger.info("User in register")

        while True:
            username = input("New username: ")
            try:
                user = user_collection.find_one({"username": username})
            except Exception as e:
                print(e)
                logger.error(f"Captured error: {e}")
                return
            if user is None:
                break
            print("The username already exists")
            logger.warning("User warning: username already exists")

        while True:
            password = input("New password: ")
            if len(password) == 0:
                print("The password cannot be empty")
                logger.warning("User warning: empty password")
            else:
                break

        password = hashlib.sha256(password.encode()).hexdigest()
        key = Fernet.generate_key()     
        
        try:
            user_collection.insert_one({"username": username, "password": password, "key": key, 'password-storage': {}})
        except Exception as e:
            print(e)
            logger.error(f"Captured error: {e}")
            return

        print("User registered successfully")
        logger.info("User registered")
    
    elif choice == "3":
        logger.info("User in password generator")

        while True:
            password_characters = input("Enter the number of characters to generate the password: ")
            try: 
                password_characters = int(password_characters)
                if (password_characters < 8 or password_characters > 32):
                    print("The number of characters must be between 8 and 32")
                    logger.warning("User warning: number of characters")
                else:
                    break
            except Exception as e:
                print("Invalid input")
                logger.error("User error: invalid input")

        logger.info("User in selection of characters")

        print("\n1. Lowercase")
        print("2. Uppercase")
        print("3. Digits")
        print("4. Special characters")
        print("5. Generate password")
        
        characters = ""
        selected_choice = ''

        while True:
            choice = input("Enter your choice(s): ")
            if choice in selected_choice:
                print("Characters already selected")
                logger.warning("User warning: characters already selected")
                continue
            if choice == "1":
                characters += string.ascii_lowercase
            elif choice == "2":
                characters += string.ascii_uppercase
            elif choice == "3":
                characters += string.digits
            elif choice == "4":
                characters += punctuation()
            elif choice == "5":
                break
            else:
                print("Invalid choice")
                logger.error("User error: invalid choice")
                continue
            selected_choice += choice
        
        password = generatePassword(password_characters, list(characters))
        print(f"Generated password: {password}")

        while True:
            print("1. Generate another password")
            print("2. Exit")
            choice = input("Enter your choice: ")
            if choice == "1":
                password = generatePassword(password_characters, list(characters))
                print(f"Generated password: {password}")
                logger.info("User generated another password")
            elif choice == "2":
                logger.info("User leave password generator")
                break
            else:
                print("Invalid choice")
                logger.error("User error: invalid choice")
        print("Goodbye!")
        return

    elif choice == "4":
        print("Goodbye!")
        logger.info("User leave mypass")
        return
    
    else:
        print("Invalid choice")
        logger.error("User error: invalid choice")
        return

    # Get the user encryption key
    try:
        user = user_collection.find_one({"username": username})
        key = user.get("key")
    except Exception as e:
        print(e)
        logger.error(f"Captured error: {e}")
        return
    
    # Create the password manager
    password_manager = PasswordManager(key, user_collection, username)

    logger.info("Logged user in password manager")

    # Main menu
    while True:
        print("\n1. Add password")
        print("2. List all keywords")
        print("3. Recover password")
        print("4. Delete password")
        print("5. Update password")
        print("6. Exit")
        choice = input("Enter your choice: ")
        print("")

        # Add password
        if choice == "1":
            logger.info("Logged user in add password")
            keyword = input("Enter a keyword: ")
            password = input("Enter a password: ")
            try:
                password_manager.add_password(keyword, password)
                print("Password stored successfully")
                logger.info("Logged user stored password")
            except Exception as e:
                print(e)
                logger.error(f"Captured error: {e}")
        
        # List all keywords
        elif choice == "2":
            logger.info("Logged user in list all keywords")
            try:
                keywords = password_manager.get_all_keywords()
                print("Keywords:")
                for keyword in keywords:
                    print("- " + keyword)
            except Exception as e:
                print(e)
                logger.error(f"Captured error: {e}")

        # Recover password
        elif choice == "3":
            logger.info("Logged user in recover password")
            keyword = input("Enter the keyword: ")
            try:
                password = password_manager.recover_password(keyword)
                print(f"The password is: {password}")
                logger.info("Logged user recovered password")
            except Exception as e:
                print(e)
                logger.error(f"Captured error: {e}")
        
        # Delete password
        elif choice == "4":
            logger.info("Logged user in delete password")
            keyword = input("Enter the keyword: ")
            try:
                password_manager.delete_password(keyword)
                print("Password deleted successfully")
                logger.info("Logged user deleted password")
            except Exception as e:
                print(e)
                logger.error(f"Captured error: {e}")
        
        # Update password
        elif choice == "5":
            logger.info("Logged user in update password")
            keyword = input("Enter the keyword: ")
            new_password = input("Enter the new password: ")
            try:
                password_manager.update_password(keyword, new_password)
                print("Password updated successfully")
                logger.info("Logged user updated password")
            except Exception as e:
                print(e)
                logger.error(f"Captured error: {e}")
        
        # Exit
        elif choice == "6":
            logger.info("Logged user leave mypass")
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice")
            logger.error("User error: invalid choice")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nGoodbye!")
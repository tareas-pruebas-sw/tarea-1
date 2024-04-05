import string

from punctuation import punctuation
from mongo import get_user_collection
from password_generator import generatePassword
from password_manager import PasswordManager

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
        username = input("Enter your username: ")
        password = input("Enter your password: ")

        '''
        Here we should implement the login functionality
        '''
    
    elif choice == "2":
        '''
        Here we should implement the register functionality
        '''
        return
    
    elif choice == "3":

        while True:
            password_characters = input("Enter the number of characters to generate the password: ")
            try: 
                password_characters = int(password_characters)
                if (password_characters < 8 or password_characters > 32):
                    print("The number of characters must be between 8 and 32")
                else:
                    break
            except Exception as e:
                print("Invalid input")

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
            elif choice == "2":
                break
            else:
                print("Invalid choice")
        print("Goodbye!")
        return

    elif choice == "4":
        print("Goodbye!")
        return
    
    else:
        print("Invalid choice")
        return

    # Get the user encryption key
    try:
        user = user_collection.find_one({"username": username})
        key = user.get("key")
    except Exception as e:
        print(e)
        return
    
    # Create the password manager
    password_manager = PasswordManager(key, user_collection, username)

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
            keyword = input("Enter a keyword: ")
            password = input("Enter a password: ")
            try:
                password_manager.add_password(keyword, password)
                print("Password stored successfully")
            except Exception as e:
                print(e)
        
        # List all keywords
        elif choice == "2":
            try:
                keywords = password_manager.get_all_keywords()
                print("Keywords:")
                for keyword in keywords:
                    print("- " + keyword)
            except Exception as e:
                print(e)

        # Recover password
        elif choice == "3":
            keyword = input("Enter the keyword: ")
            try:
                password = password_manager.recover_password(keyword)
                print(f"The password is: {password}")
            except Exception as e:
                print(e)
        
        # Delete password
        elif choice == "4":
            keyword = input("Enter the keyword: ")
            try:
                password_manager.delete_password(keyword)
                print("Password deleted successfully")
            except Exception as e:
                print(e)
        
        # Update password
        elif choice == "5":
            keyword = input("Enter the keyword: ")
            new_password = input("Enter the new password: ")
            try:
                password_manager.update_password(keyword, new_password)
                print("Password updated successfully")
            except Exception as e:
                print(e)
        
        # Exit
        elif choice == "6":
            break
        
        else:
            print("Invalid choice")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nGoodbye!")
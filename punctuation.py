import string

def punctuation():
    print(string.punctuation)
    while True:
        selectedPunctuation = input("Select symbols: ")
        if len(selectedPunctuation) == 0:
            print("Please select at least one symbol")
        else:
            error = 0
            for i in selectedPunctuation:
                if i not in string.punctuation:
                    error = 1
            if error == 1:
                print("Please select a valid symbol")
            else:
                break
    selected = ''
    for i in string.punctuation:
        if i in selectedPunctuation:
            selected += str(i)
    return selected

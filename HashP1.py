import hashlib
import bcrypt

# Function that reads in the file and provide a hash in the requested algorithm
def hash_txt(alg, file):
    with open(file, "rb") as f:
        if alg == "MD5":
            digest = hashlib.md5()
        elif alg == "SHA1":
            digest = hashlib.sha1()
        elif alg == "SHA256":
            digest = hashlib.sha256()
        else:
            print("Unsupported algorithm, please try again")
            return None
            
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()

# Generates a salt and hashes the password with the salt. The strength of the salt is based on the how many times the user wants but requires more computional power the higher the amount of times
def hash_pass(pwd, times):
    salt = bcrypt.gensalt(times)
    hpw = bcrypt.hashpw(pwd.encode('utf-8'), salt)
    return hpw

# Asks user for whether they like to hash file or hash pass. Takes user input and prints output
if __name__ == "__main__":
    choice = input("1. Hashing File\n2. Hashing Passwords\nChoose your option (Accepts numbers, option, short hand i.e 1, Hashing File, HF): ")
    if choice == "1" or choice.lower() == "hashing file" or choice.lower() == "hf":
        Alg = input("Choose your hashing algorithm: ")
        File = input("Enter path to file: ")
        ht = hash_txt(Alg.upper(), File)
        if ht != None:
            print(f"{Alg}: {ht}")
    elif choice == "2" or choice.lower() == "hashing password" or choice.lower() == "hp":
        pw = input("Enter password to hash: ")
        time = int(input("Enter how many times you would like to stretch the key: "))
        hp = hash_pass(pw, time)
        print(f"{hp}")
    else:
        print("Not a valid choice, please try again")
    

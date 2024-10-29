import os
import time
import random
import string

def generate_random_filename(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length)) + '.txt'

def create_and_delete_files():
    

    while True:
        
        filename = generate_random_filename()
        
        
        with open(filename, 'w') as f:
            f.write('This is a temporary file.')

        print(f"Created file: {filename}")
        time.sleep(6)
        os.remove(filename)
        print(f"Deleted file: {filename}")

if __name__ == "__main__":
    create_and_delete_files()

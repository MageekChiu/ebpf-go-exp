import os
import time
import random
import string

def generate_random_filename(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length)) + '.txt'

def generate_random_foldername(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def create_and_delete_files():
    
    while True:
        filename = generate_random_filename()
        with open(filename, 'w') as f:
            f.write('This is a temporary file.')
        print(f"Created file: {filename}")
        time.sleep(3)
        os.remove(filename)
        print(f"Deleted file: {filename}")

        foldername = generate_random_foldername()
        os.makedirs(foldername)
        print(f"Created folder: {foldername}")
        time.sleep(3)
        os.rmdir(foldername)  # 删除空文件夹
        print(f"Deleted folder: {foldername}")

if __name__ == "__main__":
    create_and_delete_files()

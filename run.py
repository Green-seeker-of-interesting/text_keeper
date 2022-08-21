import sys
import base64
import hashlib

from cryptography.fernet import Fernet

PATH_INDEX = 2
MODE_INDEX = 1


def main():
    mode_work, path_to_fail = get_system_argument()
    if mode_work == "-c":
        coding_worker(path_to_fail)
    elif mode_work == "-e":
        decoding_worker(path_to_fail)
    else:
        print("Неопределённая операция")


def get_system_argument() -> tuple:
    mode_work = sys.argv[MODE_INDEX]
    path = sys.argv[PATH_INDEX]
    return mode_work, path


def coding_worker(path):
    data = read_file(path)
    coding_data = cipher(data=data, automatic_key=False)
    write_to_faile(path, coding_data)


def decoding_worker(path):
    data = read_file(path)
    try:
        decoding_data = decryptor(data)
        write_to_faile(path, decoding_data)
    except:
        print("Неверный пароль")


def cipher(data: bytes, automatic_key: bool) -> bool:
    cipher_fernet = Fernet(key_generation(automatic_key=automatic_key))
    return cipher_fernet.encrypt(data)


def decryptor(data: bytes):
    decyptor_fernet = Fernet(manual_key())
    return decyptor_fernet.decrypt(data)


def key_generation(automatic_key: bool = True):
    if automatic_key:
        return Fernet.generate_key()
    else:
        return manual_key()


def manual_key() -> bytes:
    password = input("Введите пароль ")
    return base64.urlsafe_b64encode(hashlib.md5(password.encode()).hexdigest().encode())


def read_file(name: str) -> bytes:
    with open(name, 'rb') as f:
        return f.read()


def write_to_faile(name: str, data: str) -> None:
    with open(name, "wb") as f:
        f.write(data)


if __name__ == "__main__":
    main()

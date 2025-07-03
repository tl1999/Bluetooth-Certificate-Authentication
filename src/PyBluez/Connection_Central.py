import datetime
import os
import subprocess
import time
import threading

# import bluetooth
from bluetooth import *
from cryptography import x509
from cryptography.hazmat.primitives import cmac, hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.x509.verification import PolicyBuilder, Store
import click
import fileinput
import re

BLUETOOTH_PARAMETERS_PATH_LINUX = "/var/lib/bluetooth/"

CA_CERT_FILE = "cert_CA.crt"

RSA_KEY_FILE = "rsa_key.pem"
RSA_PASSWORD = None
RSA_CERT_FILE = "cert_RSA.crt"

ECDH_KEY_FILE = "ecdh_key.pem"
ECDH_PASSWORD = None
ECDH_CERT_FILE = "cert_DH.crt"

DEFAULT_BDADDR = "DC:A6:32:1D:AE:54"

USE_CONNECTION_VALUES = False
BOTH_SYSTEMS = True 

valid = False
    
def is_device_paired(device_address):
    """Check if the device is already paired."""
    try:
        # Run bluetoothctl to list paired devices
        result = subprocess.run(
            ["bluetoothctl", "devices", "Paired"], check=True, capture_output=True, text=True
        )
        
        # Check if the device address is in the list of paired devices
        paired_devices = result.stdout
        if device_address in paired_devices:
            print(f"Device {device_address} is already paired.")
            return True
        else:
            print(f"Device {device_address} is not paired.")
            return False
    except subprocess.CalledProcessError as e:
        print(f"Error while checking paired devices: {e}")
        return False

def connect(remote_addr):
    if USE_CONNECTION_VALUES:
        if is_device_paired(remote_addr):            
            subprocess.run(["sudo", "bluetoothctl", "remove", remote_addr], check=True)
    else: 
        if is_device_paired(remote_addr):
            # If the device has only established one key, start the pairing process whatsoever!
            print("Device is already paired")
            time.sleep(15)
            return None
    
    
    # Start bluetoothctl in interactive mode
    process = subprocess.Popen(
        ["bluetoothctl", "-a", "NoInputNoOutput"],
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True
    )

    # process.stdin.write("menu scan\n")
    # process.stdin.flush()

    # process.stdin.write("clear all\n")
    # process.stdin.flush()

    # process.stdin.write("rssi -60\n")
    # process.stdin.flush()

    # process.stdin.write("back\n")
    # process.stdin.flush()

    # process.stdin.write("discoverable on\n")
    # process.stdin.flush()

    # Run 'scan on' and wait for the device to appear

    # process.stdin.write("agent NoInputNoOutput\n")
    # process.stdin.write("default-agent\n")
    # process.stdin.write("power on\n")
    # process.stdin.flush()

    time.sleep(2)
    
    print(f"Scanning for device {remote_addr}...")
    process.stdin.write("scan on\n")
    process.stdin.flush()

    # Run 'pair' command for the specified device
    print("Waiting for device to appear...")
    while True:
        print("Scanning...")
        line = process.stdout.readline()
        print(line.strip())
        if not line:
            print("No output from bluetoothctl.")
            continue
        if "Device" in line and remote_addr in line and "DEL" not in line:
            print(f"Found device: {line.strip()}")
            break

    print(f"Attempting to pair with {remote_addr}...")
    process.stdin.write(f"pair {remote_addr}\n")
    process.stdin.flush()
    
    # if access is requested by the device, user has to accept it
    # print("Waiting for user confirmation...")
    # while True:
    #     line = process.stdout.readline()
    #     print(line.strip())
    #     if not line:
    #         break
    #     if "(yes/no)" in line:
    #         print("Device requested access")
    #         answer = input("Accept connection? (yes/no): ").strip().lower()
    #         process.stdin.write(answer + "\n")
    #         process.stdin.flush()
    #         break

    # print("Waiting for pairing confirmation...")

    # # Accept connection
    # process.stdin.write("yes\n")
    # process.stdin.flush()

    # Run 'scan off' to stop scanning
    process.stdin.write("scan off\n")
    process.stdin.flush()
    
    while True:
        line = process.stdout.readline()
        if not line:
            break
        if "Pairing successful" in line:
            break

    process.stdin.write("discoverable off\n")
    process.stdin.flush()

    # Close the interactive session
    process.stdin.write("exit\n")
    process.stdin.flush()

    # Collect the output from bluetoothctl
    _,stderr = process.communicate()

    # Check for errors in stderr
    if stderr:
        print("Errors:")
        print(stderr)

    process.stdin.close()
    process.stdout.close()
    process.stderr.close()
    process.terminate()

    print("Test connection successful")

def start_communication(remote_addr):
    # Connect to the server
    port = 0x1001

    error_sock = BluetoothSocket(L2CAP)
    error_sock.set_l2cap_mtu(4096)
    # error_sock.setl2capsecurity(4)
    error_sock.connect((remote_addr, port))
    
    sock=BluetoothSocket(L2CAP)
    sock.set_l2cap_mtu(4096)
    # sock.setl2capsecurity(4)
    sock.connect((remote_addr,port))
    
    return sock, error_sock

def get_LK(remote_addr, addr):

    # Open file
    file = open("/var/lib/bluetooth/" + addr + "/" + remote_addr + "/info", "r")
    data = file.read()
    file.close()
    
    # Read out the key
    key = None
    next_line = False
    for line in data.split("\n"):
        if "Key=" in line and next_line:
            key = line.split("=")[1].strip()
        next_line = False
        if "LinkKey" in line:
            next_line = True
    
    return bytes.fromhex(key)

def get_LTK(remote_addr, addr):

    # Open file
    file = open("/var/lib/bluetooth/" + addr + "/" + remote_addr + "/info", "r")
    data = file.read()
    file.close()
    
    # Read out the key
    key = None
    next_line = False
    for line in data.split("\n"):
        if "Key=" in line and next_line:
            key = line.split("=")[1].strip()
        next_line = False
        if "LongTermKey" in line:
            next_line = True
    
    return bytes.fromhex(key)

def validate_cert(cert, addr):
    
    with open("cert_CA.crt", "rb") as f:
        store = Store([x509.load_pem_x509_certificate(f.read())])

    utc_now = datetime.datetime.now(datetime.timezone.utc)
    cet_offset = datetime.timezone(datetime.timedelta(hours=1))
    cet_time = utc_now.astimezone(cet_offset)

    builder = PolicyBuilder().store(store)
    builder = builder.time(cet_time)
    verifier = builder.build_client_verifier()
    verified_client = verifier.verify(cert, [])

    if not cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE).value.digital_signature: 
        raise RuntimeError("This certificate is not valid for digital signatures")
 
    name = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

    if addr in name:
        print("Found")
    else:
        raise RuntimeError("The certificate is not valid for this device")
    
    # Get the public key from the certificate
    pubkey = cert.public_key()

    return pubkey

def store_authenticate(remote_addr, addr):
    with fileinput.input(files=(BLUETOOTH_PARAMETERS_PATH_LINUX + addr + "/" + remote_addr + "/info"), inplace=True) as file:
        for line in file:
            if re.search(r'Type=\d+', line):
                line = "Type=8\n"
            if re.search(r'Authenticated=\d+', line):
                line = "Authenticated=3\n"
            if re.search(r'Authenticated=(true|false)', line):
                line = "Authenticated=true\n"
            print(line, end='')
    return
   

def scheme_BLE_Signature_verify(sock, remote_addr):
    sock.send(b'1')

    print("Starting BLE Signature scheme")

    # Request
    challA = os.urandom(16)
    sock.send(challA)

    # Response
    signature = sock.recv(256)
    challB = sock.recv(16)
    PairReq = sock.recv(6)

    # Receive the length of the certificate first
    certLengthBytes = sock.recv(4)
    certLength = int.from_bytes(certLengthBytes, 'big')
    receivedBytes = sock.recv(certLength)
    nonce = sock.recv(16)
    cert = x509.load_pem_x509_certificate(receivedBytes)

    # AES with LTK
    encryptor = Cipher(algorithms.AES(get_LTK(remote_addr, sock.getsockname()[0] )), modes.CTR(nonce)).encryptor()
    authData = encryptor.update(challB) + encryptor.finalize()

    # Verify certificate and get public key
    try:
        pubkey = validate_cert(cert, remote_addr )
    except Exception as e:
        raise RuntimeError(f"Certificate is invalid: {e}")

    # Verify signature with public key
    try:
        message = authData + challA + challB + PairReq
        pubkey.verify(signature, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        print("Signature is valid")
    except Exception as e:
        raise RuntimeError(f"Signature is invalid: {e}")
    
    global valid
    valid = True

    sock.send(b'1')

    try:
        scheme_BLE_Signature_authenticate(sock, remote_addr, PairReq)
    except Exception as e:
        print(f"Error during authentication: {e}")
        raise
    return

def scheme_BLE_DH_verify(sock, remote_addr):
    sock.send(b'2')

    print("Starting BLE DH scheme")

    # Exchange ECDH keys
    authskDH = ec.generate_private_key(ec.SECP256R1())
    authpkDH = authskDH.public_key()

    sock.send(authpkDH.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    # Request
    challA = os.urandom(16)
    sock.send(challA)

    # Response
    signature = sock.recv(16)
    challB = sock.recv(16)
    PairReq = sock.recv(6)

    # Receive the length of the certificate first
    certLengthBytes = sock.recv(4)
    certLength = int.from_bytes(certLengthBytes, 'big')
    receivedBytes = sock.recv(certLength)
    nonce = sock.recv(16)
    cert = x509.load_pem_x509_certificate(receivedBytes)

    # AES with LTK
    encryptor = Cipher(algorithms.AES(get_LTK(remote_addr, sock.getsockname()[0])), modes.CTR(nonce)).encryptor()
    authData = encryptor.update(challB) + encryptor.finalize()

    # Verify certificate and get public key
    try:
        pubkey = validate_cert(cert, remote_addr)
    except Exception as e:
        raise RuntimeError(f"Certificate is invalid: {e}")
    
    # Calculate shared key  
    shared_key = authskDH.exchange(ec.ECDH(), pubkey)

    # Verify signature with public key
    try:
        i0 = b'0'*3
        a0 = b'0'*len(remote_addr)

        message = challA + challB + authData + i0 + a0 + PairReq

        c = cmac.CMAC(algorithms.AES(shared_key))
        c.update(message)
        c.verify(signature)
        print("Signature is valid")
    except Exception as e:
        raise RuntimeError(f"Signature is invalid: {e}")
    
    global valid
    valid = True
    
    sock.send(b'1')

    try:
        scheme_BLE_DH_authenticate(sock, remote_addr, PairReq)
    except Exception as e:
        print(f"Error during authentication: {e}")
        raise

    return

def scheme_BR_Signature_verify(sock, remote_addr):
    sock.send(b'3')

    print("Starting BR/EDR Signature scheme")

    # Request
    challA = os.urandom(16)
    sock.send(challA)

    # Response
    signature = sock.recv(256)
    challB = sock.recv(16)
    IOcap = sock.recv(3)

    # Receive the cert
    certLengthBytes = sock.recv(4)
    certLength = int.from_bytes(certLengthBytes, 'big')
    receivedBytes = sock.recv(certLength)
    cert = x509.load_pem_x509_certificate(receivedBytes)

    # HMAC with LK
    cipher = hmac.HMAC(get_LK(remote_addr, sock.getsockname()[0]), hashes.SHA256())
    cipher.update(challB + challA)
    authData = cipher.finalize()

    # Verify certificate and get public key
    try:
        pubkey = validate_cert(cert, remote_addr )
    except Exception as e:
        raise RuntimeError(f"Certificate is invalid: {e}")

    # Verify signature with public key
    try:
        message = authData + IOcap
        pubkey.verify(signature, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        print("Signature is valid")
    except Exception as e:
        raise RuntimeError(f"Signature is invalid: {e}")
    
    global valid
    valid = True
    
    sock.send(b'1')
    try:
        scheme_BR_Signature_authenticate(sock, remote_addr, IOcap)
    except Exception as e:
        print(f"Error during authentication: {e}")
        raise
    
    return

def scheme_BR_DH_verify(sock, remote_addr):
    sock.send(b'4')

    print("Starting BR/EDR DH scheme")

    # Exchange ECDH keys
    authsk = ec.generate_private_key(ec.SECP256R1())
    authpk = authsk.public_key()
    sock.send(authpk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    
    # Request
    challA = os.urandom(16)
    sock.send(challA)

    # Response 
    signature = sock.recv(256)
    challB = sock.recv(16)
    IOCap = sock.recv(3)

    # Receive the length of the certificate first
    certLengthBytes = sock.recv(4)
    certLength = int.from_bytes(certLengthBytes, 'big')
    receivedBytes = sock.recv(certLength)
    cert = x509.load_pem_x509_certificate(receivedBytes)

    # HMAC with LK
    lk = get_LK(remote_addr, sock.getsockname()[0])
    h = hmac.HMAC(lk, hashes.SHA256())
    h.update(challA + challB)
    authData = h.finalize()

    # Verify certificate and get public key
    try:
        pubkey = validate_cert(cert, remote_addr )
    except Exception as e:
        raise RuntimeError(f"Certificate is invalid: {e}")

    # Calculate shared key    
    sharedkey = authsk.exchange(ec.ECDH(), pubkey)

    # Verify signature with public key
    try:
        message = challA + challB + authData + IOCap + b'0'*len(remote_addr )*2
        c = hmac.HMAC(sharedkey, hashes.SHA256())
        c.update(message)
        c.verify(signature)
        print("Signature is valid")
    except Exception as e:
        raise RuntimeError(f"Signature is invalid: {e}")
    
    global valid
    valid = True
    
    sock.send(b'1')
    try:
        scheme_BR_DH_authenticate(sock, remote_addr, IOCap)
    except Exception as e:
        print(f"Error during authentication: {e}")
        raise
    
    return


def scheme_BLE_Signature_authenticate(sock, remote_addr, PairReq):

    # Response
    challA = sock.recv(16)
    challB = os.urandom(16)

    # open PEM key file
    with open(RSA_KEY_FILE, "rb") as key_file:
        key = serialization.load_pem_private_key(
            key_file.read(),
            password=RSA_PASSWORD,
        )

    ltk = get_LTK(remote_addr, sock.getsockname()[0])

    # AES with LTK 
    nonce = 0
    while nonce == 0:
        nonce = os.urandom(16)
    encryptor = Cipher(algorithms.AES(ltk), modes.CTR(nonce)).encryptor()
    authData = encryptor.update(challB) + encryptor.finalize()

    # sign message with private key
    message = authData + challA + challB + PairReq
    signature = key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), # use another padding (padding.PSS) for better security  https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-serialization
        hashes.SHA256()
    )

    # open PEM key file and certificate
    with open(RSA_CERT_FILE, "r") as f:
        cert = f.read()

    # Send all data required for the server to verify the signature
    sock.send(signature)
    sock.send(challB)
    sock.send(PairReq)
    cert_length = len(cert)
    sock.send(cert_length.to_bytes(4, 'big'))
    sock.send(cert)
    sock.send(nonce)
    
    return

def scheme_BLE_DH_authenticate(sock, remote_addr, PairReq):

    # Exchange ECDH keys
    with open(ECDH_KEY_FILE, "rb") as key_file:
        authskDH_P = serialization.load_pem_private_key(
            key_file.read(),
            password=ECDH_PASSWORD,
        )
    
    authpkDH_C = serialization.load_pem_public_key(sock.recv(178))
    sharedKey = authskDH_P.exchange(ec.ECDH(), authpkDH_C)

    # Response
    challA = sock.recv(16)
    challB = os.urandom(16)
    ltk = get_LTK(remote_addr, sock.getsockname()[0])

    # AES with LTK
    nonce = 0
    while nonce == 0:
        nonce = os.urandom(16)
    encryptor = Cipher(algorithms.AES(ltk), modes.CTR(nonce)).encryptor()
    authData = encryptor.update(challB) + encryptor.finalize()

    # sign message with private key
    i0 = b'0'*3
    a0 = b'0'*len(remote_addr)

    message = challA + challB + authData + i0 + a0 + PairReq
    c = cmac.CMAC(algorithms.AES(sharedKey))
    c.update(message)
    signature = c.finalize()

    with open(ECDH_CERT_FILE, "r") as f:
        cert = f.read()

    # Send all data required for the server to verify the signature
    sock.send(signature)
    sock.send(challB)
    sock.send(PairReq)
    cert_length = len(cert)
    sock.send(cert_length.to_bytes(4, 'big'))
    sock.send(cert)
    sock.send(nonce)

    return

def scheme_BR_Signature_authenticate(sock, remote_addr, IOcap):
    # Start communication and send the chosen scheme

    # Respond
    challA = sock.recv(16)
    challB = os.urandom(16)

    # open PEM key file
    with open(RSA_KEY_FILE, "rb") as key_file:
        key = serialization.load_pem_private_key(
            key_file.read(),
            password=RSA_PASSWORD,
        )

    lk = get_LK(remote_addr, sock.getsockname()[0])

    # HMAC with LK
    cipher = hmac.HMAC(lk, hashes.SHA256())
    cipher.update(challB + challA)
    authData = cipher.finalize()

    # sign message with private key
    message = authData + IOcap
    signature = key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    # open PEM key file and certificate
    with open(RSA_CERT_FILE, "r") as f:
        cert = f.read()

    # Send all data required for the server to verify the signature
    sock.send(signature)
    sock.send(challB)
    sock.send(IOcap)
    cert_length = len(cert)
    sock.send(cert_length.to_bytes(4, 'big'))
    sock.send(cert)
    return

def scheme_BR_DH_authenticate(sock, remote_addr, IOcap):

    # Exchange ECDH keys
    with open(ECDH_KEY_FILE, "rb") as key_file:
        authskDH_P = serialization.load_pem_private_key(
            key_file.read(),
            password=ECDH_PASSWORD,
        )
    
    authpkDH_C = serialization.load_pem_public_key(sock.recv(178))
    sharedKey = authskDH_P.exchange(ec.ECDH(), authpkDH_C)

    # Response
    challA = sock.recv(16)
    challB = os.urandom(16)
    lk = get_LK(remote_addr, sock.getsockname()[0])

    # HMAC with LTK
    cipher = hmac.HMAC(lk, hashes.SHA256())
    cipher.update(challA + challB)
    authData = cipher.finalize()

    # HMAC with shared key
    message = challA + challB + authData + IOcap + b'0'*len(remote_addr)*2
    h = hmac.HMAC(sharedKey, hashes.SHA256())
    h.update(message)
    signature = h.finalize()

    with open(ECDH_CERT_FILE, "r") as f:
        cert = f.read()

    # Send all data required for the server to verify the signature
    sock.send(signature)
    sock.send(challB)
    sock.send(IOcap)
    cert_length = len(cert)
    sock.send(cert_length.to_bytes(4, 'big'))
    sock.send(cert)
    return

def error_listener(error_socket, sock, address):
    while True:
        try:
            error_message = error_socket.recv(1024).decode()
            if error_message:
                print(f"Error message from remote device: {error_message}")
                sock.close()
                subprocess.run(["sudo", "hciconfig", "hci0", "noscan"])
                subprocess.run(["sudo", "bluetoothctl", "remove", address], check=True)
                subprocess.run(["sudo", "rm", "-rf", BLUETOOTH_PARAMETERS_PATH_LINUX + sock.getsockname()[0] + "/cache/" + address], check=True)
                break
        except Exception as e:
            continue

    exit(0)

@click.command()
@click.option(
    "--system",
    type=click.Choice(
        [
            "BLE",
            "BR"
        ]
    ),
    default="BR",
    help="Select the Bluetooth mode."
)
@click.option(
    "--scheme",
    type=click.Choice(
        [
            "Signature",
            "DH"
        ]
    ),
    default="Signature",
    help="Scheme to use for authentication."
)
@click.option(
    "--address",
    default=DEFAULT_BDADDR,
    help="Bluetooth address of the peripheral device."
)
def select_mode(system, scheme, address):
    # Run Bluetooth connection
    remote_addr = address
    print(f"Connecting to {remote_addr}")
    
    if BOTH_SYSTEMS:
        print("Both systems selected")
        connect(remote_addr)


    try :
        # Get the local Bluetooth address
        sock, error_sock = start_communication(remote_addr)
    except Exception as e:
        time.sleep(25)
        sock, error_sock = start_communication(remote_addr)

    # listen for error messages in a separate thread
    error_thread = threading.Thread(target=error_listener, args=(error_sock,sock, address), daemon=True)
    error_thread.start()

    print("Connection established")

    addr = sock.getsockname()[0]

    try:
        if system == "BLE":
            if scheme == "Signature":
                scheme_BLE_Signature_verify(sock, remote_addr)
            elif scheme == "DH":
                scheme_BLE_DH_verify(sock, remote_addr)
            else:
                print("Invalid scheme selected. Type either Signature or DH")
        elif system == "BR":
            if scheme == "Signature":
                scheme_BR_Signature_verify(sock, remote_addr)
            elif scheme == "DH":
                scheme_BR_DH_verify(sock, remote_addr)
            else:
                print("Invalid scheme selected. Type either Signature or DH")
        else:
            print("Invalid mode selected. Type either BLE or EDR")
    except Exception as e:
        print(f"Authentication failed. Pairing to Device removed: {e}")
        # send error message e
        error_sock.send(str(e).encode())
        sock.close()
        error_thread.join(timeout=5)
        error_sock.close()
        subprocess.run(["sudo", "bluetoothctl", "remove", remote_addr], check=True)
        subprocess.run(["sudo", "rm", "-rf", BLUETOOTH_PARAMETERS_PATH_LINUX + addr + "/cache/" + remote_addr], check=True)
        raise

    sock.close()
    error_thread.join(timeout=5)
    error_sock.close()

    if valid: 
        print("Store authentication")
        store_authenticate(remote_addr, addr)


if __name__ == "__main__":
    
    select_mode()

    print("Authentication successful")
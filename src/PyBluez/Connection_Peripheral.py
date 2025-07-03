import os
import re
import subprocess
import threading
import time
import datetime
import fileinput

from bluetooth import *
from cryptography import x509
from cryptography.hazmat.primitives import cmac, hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.verification import PolicyBuilder, Store

BLUETOOTH_PARAMETERS_PATH_LINUX = "/var/lib/bluetooth/"

CA_CERT_FILE = "cert_CA.crt"

RSA_KEY_FILE = "rsa_key.pem"
RSA_PASSWORD = None
RSA_CERT_FILE = "cert_RSA.crt"

ECDH_KEY_FILE = "ecdh_key.pem"
ECDH_PASSWORD = None
ECDH_CERT_FILE = "cert_DH.crt"

USE_CONNECTION_VALUES = True
USE_SYSTEM = 'LE' # BR, LE
BOTH_SYSTEMS = True # True, False

valid = False

values = [None]*6

def get_IOcap(values):
    try:
        btmon_process = subprocess.Popen(
                ["btmon"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
        response = False 
        io_cap = 0x00
        oob = 0x00
        auth = 0x00           
        for line in btmon_process.stdout:
            if "IO Capability Request" in line:
                response = True
            if "IO capability" in line and response:
                print("[btmon] Found IO Capability!")
                match = re.search(r"0x([0-9A-Fa-f]+)", line)
                if match: 
                    io_cap = match.group(0)
                    print(io_cap) 
            if "OOB data" in line and response:
                print("[btmon] Found OOB data!")
                match = re.search(r"0x([0-9A-Fa-f]+)", line)
                if match: 
                    obb = match.group(0)
                    print(obb) 
            if "Authentication" in line and response:
                print("[btmon] Found Authentication data!")
                match = re.search(r"0x([0-9A-Fa-f]+)", line)
                if match: 
                    auth = match.group(0)
                    print(auth) 
                response = False
    except Exception as e:
        print(f"Error while monitoring btmon: {e}")
    finally:
        # Ensure btmon is terminated
        btmon_process.terminate()
        print("btmon process terminated")
        return io_cap, oob, auth
        
def get_PairingRequest(values):
    try:
        btmon_process = subprocess.Popen(
                ["btmon"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
        response = False 
        io_cap = 0x00
        oob = 0x00
        auth = 0x00   
        maxE = 0x00 
        iKeyDistr = 0x00
        rKeyDistr = 0x00
        for line in btmon_process.stdout:
            if "SMP: Pairing Request" in line:
                response = True
            if "IO capability" in line and response:
                print("[btmon] Found IO Capability!")
                match = re.search(r"0x([0-9A-Fa-f]+)", line)
                if match: 
                    io_cap = match.group(0)
                    print(io_cap) 
                    values[0] = io_cap
            if "OOB data" in line and response:
                print("[btmon] Found OOB data!")
                match = re.search(r"0x([0-9A-Fa-f]+)", line)
                if match: 
                    oob = match.group(0)
                    print(oob) 
                    values[1] = oob
            if "Authentication requirement" in line and response:
                print("[btmon] Found Authentication data!")
                match = re.search(r"0x([0-9A-Fa-f]+)", line)
                if match: 
                    auth = match.group(0)
                    print(auth) 
                    values[2] = auth
            if "Max encryption" in line and response:
                print("[btmon] Found Max encryption!")
                maxE = hex(int(line.split(":")[1]))
                print(maxE)
                values[3] = maxE
            if "Initiator key distribution" in line and response:
                print("[btmon] Found Initiator key distribution data!")
                match = re.search(r"0x([0-9A-Fa-f]+)", line)
                if match: 
                    iKeyDistr = match.group(0)
                    print(iKeyDistr)
                    values[4] = iKeyDistr
            if "Responder key distribution" in line and response:
                print("[btmon] Found Responder  key distribution data!")
                match = re.search(r"0x([0-9A-Fa-f]+)", line)
                if match: 
                    rKeyDistr = match.group(0)
                    print(rKeyDistr)
                    values[5] = rKeyDistr
                response = False
    except Exception as e:
        print(f"Error while monitoring btmon: {e}")
    finally:
        # Ensure btmon is terminated
        btmon_process.terminate()
        print("btmon process terminated")

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


def get_LK(remote_addr, addr):

    # Open file
    file = open(BLUETOOTH_PARAMETERS_PATH_LINUX + addr + "/" + remote_addr + "/info", "r")
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

    if key is None:
        time.sleep(1)
        # Open file
        file = open(BLUETOOTH_PARAMETERS_PATH_LINUX + addr + "/" + remote_addr + "/info", "r")
        data = file.read()
        file.close()
        # Read out the key 
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
    file = open(BLUETOOTH_PARAMETERS_PATH_LINUX + addr + "/" + remote_addr + "/info", "r")
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

    if key is None:
        time.sleep(2)  # Wait for the file to be updated if it was just created
        # Open file
        file = open(BLUETOOTH_PARAMETERS_PATH_LINUX + addr + "/" + remote_addr + "/info", "r")
        data = file.read()
        file.close()

        print("File read again to get LTK")
        print(data)
        
        # Read out the key
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

def scheme_BLE_Signature_authenticate(sock, remote_addr):

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

    if USE_CONNECTION_VALUES:
        io_cap = int(values[0], 16)
        oob = int(values[1], 16)
        auth = int(values[2], 16)
        maxE = int(values[3], 16)
        iKeyDistr = int(values[4], 16)
        rKeyDistr = int(values[5], 16)

        PairReq = bytes([io_cap, oob, auth, maxE, iKeyDistr, rKeyDistr])
    else:
        PairReq = b'0'*6

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
    sock.send(cert_length.to_bytes(2, 'big'))
    sock.send(cert)
    sock.send(nonce)

    sock.recv(1) # Wait for the server to send a response

    try:
        scheme_BLE_Signature_verify(sock, remote_addr)
    except Exception as e:  
        print(f"Error during verifying {e}")
        raise RuntimeError(f"Error during verifying {e}")
    return

def scheme_BLE_DH_authenticate(sock, remote_addr):

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

    if USE_CONNECTION_VALUES:
        io_cap = int(values[0], 16)
        oob = int(values[1], 16)
        auth = int(values[2], 16)
        maxE = int(values[3], 16)
        iKeyDistr = int(values[4], 16)
        rKeyDistr = int(values[5], 16)

        PairReq = bytes([io_cap, oob, auth, maxE, iKeyDistr, rKeyDistr])
    else:
        PairReq = b'0'*6

    # # sign message with private key
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
    sock.send(cert_length.to_bytes(2, 'big'))
    sock.send(cert)
    sock.send(nonce)

    sock.recv(1) # Wait for the server to send a response

    try:
        scheme_BLE_DH_verify(sock, remote_addr)
    except Exception as e:
        print(f"Error during verifying {e}")
        raise

    return

def scheme_BR_Signature_authenticate(sock, remote_addr):
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

    if USE_CONNECTION_VALUES:
        io_cap = int(values[0], 16)
        oob = int(values[1], 16)
        auth = int(values[2], 16)

        IOcap = bytes([io_cap, oob, auth])

    else:
        IOcap = b'000'

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
    sock.send(cert_length.to_bytes(2, 'big'))
    sock.send(cert)

    sock.recv(1) # Wait for the server to send a response

    try:
        scheme_BR_Signature_verify(sock, remote_addr)
    except Exception as e:
        print(f"Error during verifying {e}")
        raise

    return

def scheme_BR_DH_authenticate(sock, remote_addr):

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

    if USE_CONNECTION_VALUES:
        io_cap = int(values[0], 16)
        oob = int(values[1], 16)
        auth = int(values[2], 16)

        IOcap = bytes([io_cap, oob, auth])
    else:
        IOcap = b'000'

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
    sock.send(cert_length.to_bytes(2, 'big'))
    sock.send(cert)

    sock.recv(1) # Wait for the server to send a response
    try:
        scheme_BR_DH_verify(sock, remote_addr)
    except Exception as e:
        print(f"Error during verifying {e}")
        raise

    return

def scheme_BLE_Signature_verify(sock, remote_addr):

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
    
    return

def scheme_BLE_DH_verify(sock, remote_addr):

    print("Starting BLE DH scheme")

    # Exchange ECDH keys
    authskDH = ec.generate_private_key(ec.SECP256R1())
    authpkDH = authskDH.public_key()

    sock.send(authpkDH.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

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

    return

def scheme_BR_Signature_verify(sock, remote_addr):

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
    
    return

def scheme_BR_DH_verify(sock, remote_addr):

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
    lk = get_LK(remote_addr, sock.getsockname()[0] )
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
        print(f"Signature is invalid: {e}")
        raise RuntimeError(f"Signature is invalid: {e}")
    
    global valid
    valid = True
    
    return

def error_listener(error_sock, sock, server_sock, address):
    while True:
        try:
            error_message = error_sock.recv(1024).decode()
            if error_message:
                print(f"Error message from remote device: {error_message}")
                sock.close()
                server_sock.close()
                subprocess.run(["sudo", "hciconfig", "hci0", "noscan"])
                subprocess.run(["sudo", "bluetoothctl", "remove", address], check=True)
                subprocess.run(["sudo", "rm", "-rf", BLUETOOTH_PARAMETERS_PATH_LINUX + sock.getsockname()[0] + "/cache/" + address], check=True)
                break
        except Exception as e:
            continue
    exit(0)

if __name__ == '__main__':

    enable_cmd = {
        'BR': ["sudo", "hciconfig", "hci0", "piscan"],
        'LE': ["sudo", "hciconfig", "hci0", "leadv"]
    }
    disable_cmd = {
        'BR': ["sudo", "hciconfig", "hci0", "noscan"],
        'LE': ["sudo", "hciconfig", "hci0", "noleadv"]
    }

    if ( BOTH_SYSTEMS ):
        print("Both systems are used")
        subprocess.run(enable_cmd['BR'])

        if USE_CONNECTION_VALUES:
            subprocess.run(enable_cmd[USE_SYSTEM])
            thread_target = get_IOcap if USE_SYSTEM == 'BR' else get_PairingRequest
            btmon_thread = threading.Thread(target=thread_target, daemon=True, args=(values,))
            btmon_thread.start()
        else:
            subprocess.run(enable_cmd['LE'])  # Default to LE if not using connection values

        time.sleep(25)

        if USE_CONNECTION_VALUES:
            btmon_thread.join(timeout=5)
            subprocess.run(disable_cmd[USE_SYSTEM])
        else:
            subprocess.run(disable_cmd['LE'])  

        subprocess.run(disable_cmd['BR'])  # Disable BR/EDR after LE is done
    
    print("Starting scheme connection...")

    subprocess.run(enable_cmd['BR'])

    port = 0x1001
    backlog = 1

    server_sock = BluetoothSocket(L2CAP)
    server_sock.bind(("",port))
    server_sock.listen(backlog)

    # server_sock.setl2capsecurity(4)
    server_sock.set_l2cap_mtu(4096)

    error_sock, address = server_sock.accept()
    client_sock, address = server_sock.accept()

    print("Accepted connection from ",address)

    subprocess.run(disable_cmd['BR']) 

    # Determine the scheme to use
    options = client_sock.recv(1)

    # listen for error messages in a separate thread
    print("Starting error_listener thread...")
    error_thread = threading.Thread(target=error_listener, args=(error_sock,client_sock, server_sock, address[0]), daemon=True)
    error_thread.start()

    remote_addr = address[0]
    addr = client_sock.getsockname()[0]

    try:
        if options == b'1':
            scheme_BLE_Signature_authenticate(client_sock, remote_addr)
        if options == b'2':
            scheme_BLE_DH_authenticate(client_sock, remote_addr)
        if options == b'3':
            scheme_BR_Signature_authenticate(client_sock, remote_addr)
        if options == b'4':
            scheme_BR_DH_authenticate(client_sock, remote_addr)
    except Exception as e:
        print(f"Error during scheme connection. Pairing to Device removed: {e}")
        error_sock.send(str(e).encode())
        subprocess.run(["sudo", "bluetoothctl", "remove", remote_addr], check=True)
        subprocess.run(["sudo", "rm", "-rf", BLUETOOTH_PARAMETERS_PATH_LINUX + addr + "/cache/" + remote_addr], check=True)
    
    # stop the error thread
    error_thread.join(timeout=5)
    error_sock.close()
    server_sock.close()
    client_sock.close()

    if valid:
        print("Store authentication")
        store_authenticate(remote_addr, addr)

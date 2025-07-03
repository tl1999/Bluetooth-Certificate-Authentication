# Bluetooth-Certificate-Authentication
Bluetooth has several security flaws. One major flaw is its susceptibility to Man-in-the-middle attacks due to poor authentication in Bluetooth. As part of a thesis, applications are created and provided in this repository, applying authentication schemes proposed by Fischlin and Sanina [1] on top of Bluetooth to prevent the following types of attacks on Bluetooth's authentication:

-Just Works Downgrade attack[2]
-Method Confusion attack[3]
-Pairing Confusion attack[4]
-Ghost Keystroke attack[5]
-Role Confusion attack[6]
-Keysize Confusion attack[7]

Currently, the applications only support the Bluez Bluetooth stack. Two applications are provided here, supporting each different Bluetooth systems. They are named after the Bluetooth API they use to communicate with the Bluetooth adapter they are using. The PyBluez application supports classic Bluetooth, but is also able to authenticate Bluetooth Low Energy connections if both devices support dual-mode. The BlueR application supports only Low Energy Bluetooth. For each application, two programs have to be executed on the different devices wanting to authenticate a connection. 


## Table of Contents
- [Installation](#installation)
- [Preparation](#preparation)
- [Usage](#usage)
- [Settings](#settings)
- [References](#references)

## Installation
The different Applications have to be set up differently, since they are programmed with different programming languages. As mentioned before, for each application, there are two programs. One program is for the device, which starts a connection to another device. It's called Central. The other program is for the device which accepts connections. It's called Peripheral.

1. Clone the repository on both devices:
```bash
 git clone https://github.com/tl1999/Bluetooth-Certificate-Authentication.git
```

### PyBluez (src/PyBluez)
2. Create environment (https://docs.python.org/3/library/venv.html):
```bash
 python -m venv <directory>
 ```

3. Open environment:
```bash
 source <directory>/bin/activate
 ```

4. Install the libraries:
   -Cryptography
   -Click
   -PyBluez (use for this "git+https://github.com/PyBluez/PyBluez.git#egg=PyBluez")
```bash
 pip install <application>
 ```

### BlueR (src/BlueR)
The programs here are in different folders. So, depending on which device should be the peripheral and which should be the central, go into the eponymous folder.
2. Build the program:
```bash
 cargo build 
```

## Preparation
To have a successful authentication, some key pairs and certificates have to be created. Each device needs to have the files at the location of the program they are running. A certificate of the CA responsible for issuing the certificates is required. Next, each device needs its key pairs. Depending on which approach they want to use, a Diffie–Hellman keypair or an RSA keypair has to be created. For these key pairs, a certificate has to be issued by the CA and stored. The certificates need to have their Bluetooth MAC address in the common name part of the certificate. Moreover, the certificate needs to have the keyUsage extension with the digitalSignature flag set. Example certificates and required files to create them are contained in the data folder. The naming of all files used in the applications is defined in each program as constants at the beginning and can be changed.


## Usage
To run the programs, use the following command:

### PyBluez (src/PyBluez)
1. Switch to a user with root privileges
```bash
  sudo su
```

2. Open the Python environment
```bash
  source <directory>/bin/activate
```

3. Run the program. Depending on which role the current device should take on.
   Peripheral:
```bash
  python Connection_Peripheral.py
```
  Central:
```bash
  python Connection_Central.py –system [BR/BLE] –scheme [Signature/DH] -address <remote BD_ADDR>
```
  --> The user can choose between the different Bluetooth systems (BR for classic and BLE for Low-Energy) and between different approaches used for the schemes (Using Signature KeyPairs or using a Diffie–Hellman approach). The differences are more deeply expounded on in the thesis. The BD_ADDR have to be the Bluetooth MAC address of the Peripheral device in the format (00:11:22:33:44:55)

### BlueR (src/BlueR)
Depending on which role the device should take on be in the correct folder.
1. Switch to a user with root privileges
```bash
  sudo su
```

2. Run the executable file created with cargo build
   Peripheral:
```bash
  ./Connection_Peripheral
```
  Central:
```bash
  ./Connection_Central <Peripheral address> <0 or 1>
```
   
  --> The user can choose between the different approaches used for the schemes (Using Signature KeyPairs or using a Diffie–Hellman approach). 0 is for the signature approach, while 1 is for the DH approach. The differences are more deeply expounded on in the thesis. The Peripheral address has to be the Bluetooth MAC address of the Peripheral device in the format (00:11:22:33:44:55)  

## Settings
If the storage location of a file or the name, e.g. certificate or key, has changed, there is the option in each program to change the location or the name of the file to be used. Additionally, it can be the case that the storage location of the Bluetooth data is changed. Therefore, users also have the option to change the location. 

Since the Pybluez application has the option to use both Bluetooth systems, but can also be used only for Bluetooth classic, there is the possibility to activate Dual-system support with the BOTH_SYSTEMS constant. There is also the option that the PyBluez application can use the connection values, e.g. IO capability, in the authentication process to also protect against the KNOB attack. This can be activated with the constant USE_CONNECTION_VALUES. The BOTH_SYSTEM and USE_CONNECTION_VALUES have to be the same on both devices so that the application works.

## References
1.	M. Fischlin and O. Sanina (2024) Fake It till You Make It: Enhancing Security of Bluetooth Secure Connections via Deferrable Authentication:1–49. https://doi.org/10.1145/3658644.3670360
2.	 Hypponen K, Haataja KM (2007) “Nino” man-in-the-middle attack on bluetooth secure simple pairing. In: 2007 3rd IEEE/IFIP International Conference in Central Asia on Internet, pp 1–5
3.	 Tschirschnitz M von, Peuckert L, Franzen F et al. (5/24/2021 - 5/27/2021) Method Confusion Attack on Bluetooth Pairing. In: 2021 IEEE Symposium on Security and Privacy (SP). IEEE, pp 1332–1347
4.	 Claverie T, Avoine G, Delaune S et al. (2024) Tamarin-Based Analysis of Bluetooth Uncovers Two Practical Pairing Confusion Attacks. In: Springer, Cham, pp 100–119
5.	 Yue Zhang, Jian Weng, Rajib Dey et al. (2020) Breaking Secure Pairing of Bluetooth Low Energy Using Downgrade Attacks. In: 29th USENIX Security Symposium (USENIX Security 20). USENIX Association, pp 37–54
6.	Michael Troncoso, Britta Hale (2021) The Bluetooth CYBORG: Analysis of the Full Human-Machine Passkey Entry AKE Protocol. Cryptology ePrint Archive
7.	Shi M, Chen J, He K et al. (2025) Formal Analyzing, Attacking, and Patching of Bluetooth Pairing Protocols. IEEE Internet Things J 12:7955–7968. https://doi.org/10.1109/JIOT.2025.3529507

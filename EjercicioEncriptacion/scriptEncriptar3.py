import io
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Hash import SHA1
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

#########################################################
#                GENERACIÓN DE LA CLAVE                 #
#########################################################

# Generar pareja de claves RSA de 2048 bits de longitud
key = RSA.generate(2048)

# Passphrase para encriptar la clave privada
secret_code = "12345"

# Exportamos la clave privada
private_key = key.export_key(passphrase=secret_code)

# Guardamos la clave privada en un fichero
with open("private.pem", "wb") as f:
    f.write(private_key)

# Obtenemos la clave pública
public_key = key.publickey().export_key()

# Guardamos la clave pública en otro fichero
with open("public.pem", "wb") as f:
    f.write(public_key)
    
#########################################################
#                GENERACIÓN DE LA FIRMA                 #
#########################################################
# Leemos el archivo con el mensaje
with open("mensaje.txt", "r") as f:
    message = f.readlines() 
    message = ''.join(message) 
encoded_string = message.encode('ISO-8859-1')
byte_array_message = bytearray(encoded_string)
h = SHA1.new()
h.update(byte_array_message)
message_to_sign = h.hexdigest()
# Leemos el archivo con la clave privada
with open("private.pem", "rb") as f:
    recipient_key = f.read()
# Cargamos la clave privada (instancia de clase RSA)
key = RSA.importKey(recipient_key,  passphrase="12345")

# Generamos la firma y el mensaje firmado
message_to_sign = message_to_sign.encode('ISO-8859-1')
h = SHA256.new(message_to_sign)
signature = pkcs1_15.new(key).sign(h)
message_signed = signature.decode('ISO-8859-1')

# Guardamos la firma
with open("firma", "wb") as f:
    f.write(signature)
    
print('Firma: ')
print(signature)
#########################################################
#                VALIDACIÓN DE LA FIRMA                 #
#########################################################

key = RSA.import_key(open("public.pem", "rb").read())
try:
    pkcs1_15.new(key).verify(h, signature)
    print('Verificación: ')
    print('Firma verificada')
except (ValueError, TypeError) as e:
    print('Verificación: ')
    print('Firma inválida')
    
#########################################################
#                        CIFRADO                        #
#########################################################
# Cadena UTF-8 a encriptar
f = open ('mensaje.txt','r')
cadena = f.read()
print('Mensaje a cifrar: ')
print(cadena)
f.close()

# Trabajamos con bytes, codifcamos la cadena.
bin_data = cadena.encode("utf-8")

# Leemos el archivo con la clave publica
with open("public.pem", "rb") as f:
    recipient_key = f.read()

# Cargamos la clave pública (instancia de clase RSA)
key = RSA.importKey(recipient_key)

# Instancia del cifrador asimétrico
cipher_rsa = PKCS1_OAEP.new(key)

# Generamos una clave para el cifrado simétrico
aes_key = get_random_bytes(16)

# Encriptamos la clave del cifrado simétrico con la clave pública RSA
enc_aes_key = cipher_rsa.encrypt(aes_key)

# Encriptamos los datos mediante cifrado simétrico (AES en este caso)
cipher_aes = AES.new(aes_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(bin_data)

# Concatenamos la clave simétrica cifrada a los datoscifrados con ella
enc_data = b"".join((enc_aes_key, cipher_aes.nonce, tag, ciphertext))
print('Mensaje cifrado: ')
print(enc_data)
with open("mafe.enc", "wb") as f:
    f.write(enc_data)
# b'\x0f_r\xcd5%\x9a\x9bA\x14\xcdZ\xa9sl\'\x9d\xab\xea\xd2^1



#########################################################
#                     DESCIFRADO                        #
#########################################################

# Emulamos un fichero con nuestra cadena porque el método read facilita
# la división de cada parte de la cadena (datos y clave AES encriptada).
# Podríamos también obtenerlos simplemente mediante slicing de la cadena
#data_file = io.BytesIO(enc_data)
data_file = open("mafe.enc", "rb")

# Leemos el archivo con la clave privada
with open("private.pem", "rb") as f:
    recipient_key = f.read()

# Cargamos la clave pública (instancia de clase RSA)
key = RSA.importKey(recipient_key,  passphrase="12345")

# Instancia del cifrador asimétrico
cipher_rsa = PKCS1_OAEP.new(key)

# Separamos las distintas partes de la cadena cifrada
enc_aes_key, nonce, tag, ciphertext =\
    (data_file.read(c) for c in (key.size_in_bytes(), 16, 16, -1))

# Desencriptamos la clave AES mediante la clave privada RSA
aes_key = cipher_rsa.decrypt(enc_aes_key)

# Desencriptamos los datos en si con la clave AES
cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)

# Decodificamos la cadena
cadena = data.decode("utf-8")
print('Mensaje Descifrado: ')
print(cadena)
with open("mafe.des", "w") as f:
    f.write(cadena)
#Hola StackOverflow en español 

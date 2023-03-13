#!/usr/bin/env python3

import os
import zipfile

from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from flask import Flask 
from flask import request
from flask import render_template
from flask import send_file

app = Flask(__name__) 


# Probably better to do everything from Python instead of mixing tools even
# though they are compatible.
def create_rsa_key():
    # https://pycryptodome.readthedocs.io/en/latest/src/examples.html#generate-an-rsa-key
    return None


def load_private_key():
    """
    Load a private key in PEM format from a file specified by the environment
    variable AR_PRIV_KEY and return an RSA object.

    Returns:
        RSA object: the loaded private key as an RSA object.
    """

    key = None
    path = os.environ.get('AR_PRIV_KEY')
    if path is None:
        print("AR_PRIV_KEY not set as env variable")
        return key

    print(f"Found path {path}")
    with open(path, 'rb') as f:
        key = RSA.import_key(f.read())

    return key


def hash_binary(bin):
    """
    Computes the SHA-256 hash of the given binary data and returns the binary
    digest.

    Args:
        bin (bytes): the binary data to hash.

    Returns:
        bytes: the binary digest of the SHA-256 hash.

    """
    return SHA256.new(bin)


def sign_binary(key, h):
    """
    Signs a binary hash using the provided private key with PSS padding scheme.

    Parameters:
    key (Crypto.PublicKey.RSA._RSAobj): Private key to sign the hash with.
    h (bytes): Binary hash to sign.

    Returns:
    bytes: Signed binary hash.
    """
    pss_obj = pss.new(key)
    return pss_obj.sign(h)


def extract_public_key(priv_key):
    """
    Extract the public key in PEM format from a given private key.

    Args:
        priv_key: A private key in pycryptodome RSA format.

    Returns:
        A string representing the public key in PEM format.
    """
    pub_key = priv_key.publickey().export_key(format='PEM')
    return pub_key.decode()


def compress_files(fw_name, fw, digest, signature, pub_key):
    """
    Compresses multiple files and saves them to a zip file.

    Args:
        fw_name (str): Name of the firmware file.
        fw (bytes): Binary data of the firmware file.
        digest (bytes): SHA256 hash of the firmware file.
        signature (bytes): RSA-PSS signature of the firmware file.
        pub_key (str): Public key in PEM format.

    Returns:
        str: Name of the created zip file.

    """

    # FIXME: The public key shouldn't probably be here.
    files = {
            fw_name: fw,
            'fw.sha256': digest,
            'fw.sig': signature,
            'pub_key.pem': pub_key
    }
    
    # Strip the suffix
    fw_name, _ = os.path.splitext(fw_name)

    # Create the zip-file.
    zipfile_name = f"ar_{fw_name}.zip"
    with zipfile.ZipFile(zipfile_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for filename, data in files.items():
            print(f"{filename}")
            zipf.writestr(filename, data)

    return zipfile_name


# FIXME: ACS not used here. It's > 600MB when not compressed. Let's deal with
# that later when we have a better idea of how to sign things.
def create_compressed_signed_binaries(fw = None, fw_name = None, acs = None):
    """
    Compresses the firmware file and signs it using a private key, and returns
    the resulting file to the caller.

    Args:
        fw (bytes): The firmware binary file as a byte string.
        fw_name (str): The name of the firmware file.
        acs (str): The link to the ACS.

    Returns:
        A Flask `send_file` object containing the signed and compressed firmware file.

    Raises:
        ValueError: If either the firmware or firmware name is None.

    """
    h = hash_binary(fw)

    priv_key = load_private_key()
    pub_key = extract_public_key(priv_key)
    signature = sign_binary(priv_key, h)

    my_zipfile = compress_files(fw_name, fw, h.digest(), signature, pub_key)

    return send_file(my_zipfile, as_attachment=True)


# Code if we need to send the zip-file to a remote server instead
#   with open(my_zipfile, 'rb') as f:
#       headers = {'Content-Type': 'application/octet-stream'}
#       url = 'http://localhost'
#       response = requests.post(url, data=f.read(), headers=headers)
#       if response.status_code == 200:
#           return 'File uploaded successfully'
#       else:
#           print('Error:', response.status_code)
#           abort(400, 'No file sent')


@app.route('/upload', methods=['POST'])
def upload():
        firmware = request.files['firmware']
        firmware_binary = firmware.read()
        #acs = request.files['ACS']
        #acs_binary = acs.read()
        return create_compressed_signed_binaries(firmware_binary,
                                                 firmware.filename, None)


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('upload.html')


if __name__ == "__main__":
    app.run()

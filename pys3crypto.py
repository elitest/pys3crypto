#!/usr/bin/env python3
# Original Author @elitest

# This script uses boto3 to perform client side decryption
# of data encryption keys and associated files
# and encryption in ways compatible with the AWS SDKs
# This support is not available in boto3 at this time

# Wishlist:
# Currently only tested with KMS managed symmetric keys.
# Error checking

import boto3, argparse, base64, json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

# Build the parser
argparser = argparse.ArgumentParser(description='Prints info about deleted items in s3 buckets and helps you download them.')
argparser.add_argument('bucket', help='The bucket that contains the file.')
argparser.add_argument('region', help='The region the CMK is in.')
argparser.add_argument('key', help='The name of the file that you would like to download and decrypt.')
argparser.add_argument('--profile', default='default', help='The profile name in ~/.aws/credentials')
args = argparser.parse_args()

# Set variables from arguments
bucket = args.bucket
region = args.region
profile = args.profile
key = args.key

# Setup AWS clients
boto3.setup_default_session(profile_name=profile, region_name=region)

s3_client = boto3.client('s3')
response = s3_client.get_object(Bucket=bucket,Key=key)
kms_client = boto3.client('kms')

# This function decrypts the encrypted key associated with the file
# and decrypts it
def decrypt_dek(metadata):
        # Encrypted key
	keyV2 = base64.b64decode(metadata['Metadata']['x-amz-key-v2'])
        # Key ARN
	context = json.loads(metadata['Metadata']['x-amz-matdesc'])
        # This decrypts the DEK using KMS 
	dek = kms_client.decrypt(CiphertextBlob=keyV2, EncryptionContext=context)
	return dek['Plaintext']


def decrypt(key, algo, iv, ciphertext, tag):
    if algo == 'AES/GCM/NoPadding':
        # Construct a Cipher object, with the key, iv, and additionally the
        # GCM tag used for authenticating the message.
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        # Decryption gets us the authenticated plaintext.
        # If the tag does not match an InvalidTag exception will be raised.
        return decryptor.update(ciphertext) + decryptor.finalize()
    elif algo == 'AES/CBC/PKCS5Padding':
        # Construct a Cipher object, with the key, iv
        decryptor = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        ).decryptor()
        # Decryption gets us the plaintext.
        data = decryptor.update(ciphertext) + decryptor.finalize()
        # Apparently PKCS5 and 7 are basically the same for our purposes
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(data) + unpadder.finalize()
    else:
        print('Unknown algorithm or padding.')
        exit()

# Decrypt the DEK
plaintextDek = decrypt_dek(response)
# Get the encrypted body
# Haven't tested with large files
body=response['Body'].read()
# We need the content length for GCM to build the tag
contentLen = response['Metadata']['x-amz-unencrypted-content-length']
# IV
iv = base64.b64decode(response['Metadata']['x-amz-iv'])
# Algorithm
alg = response['Metadata']['x-amz-cek-alg']
# This splits the tag and data from the body if GCM
if alg == 'AES/GCM/NoPadding':
    data = body[0:int(contentLen)]
    tagLen = response['Metadata']['x-amz-tag-len']
    tag = body[int(contentLen):int(tagLen)]
else:
    data = body[:]
    tag = ''
# Decrypt the file
plaintext = decrypt(plaintextDek,alg,iv,data,tag)
print(plaintext)

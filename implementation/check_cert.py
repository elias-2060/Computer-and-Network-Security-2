import OpenSSL


def check_certificate(checked_crt: str, ca_crt: str, public_key_output_path: str):
    """ Validates a x509 certificate against a CA certificate using OpenSSL, if it passed the validation it
    saves the public key of the validated certificate."""
    try:
        # Load the certificate we want to validate
        with open(checked_crt, 'rb') as cert_file:
            cert_data = cert_file.read()
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data)

        # Load the CA certificate
        with open(ca_crt, 'rb') as ca_file:
            ca_data = ca_file.read()
        ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, ca_data)

        # Create a store for the ca certificate to verify it against our certificate
        store = OpenSSL.crypto.X509Store()
        # Add the ca certificate to the store
        store.add_cert(ca)

        # Create a certificate context with the store and our certificate to verify it
        store_ctx = OpenSSL.crypto.X509StoreContext(store, cert)
        # Verify the certificate
        store_ctx.verify_certificate()

        # Save the public key because the verification passed
        public_key = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey())
        with open(public_key_output_path, 'wb') as key_file:
            key_file.write(public_key)
        return True

    except OpenSSL.crypto.X509StoreContextError:
        # Certificate validation failed
        return False
    except Exception:
        # Other errors (file handling)
        return False
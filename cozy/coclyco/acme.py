import os
from time import sleep

import OpenSSL
import acme.challenges
import acme.client
import josepy
import acme.messages
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, \
    PrivateFormat, NoEncryption
from pyasn1.codec.der import decoder
from pyasn1_modules.rfc2459 import SubjectAltName

from .logger import Logger


class ACME:
    ACME_STAGING = os.getenv("ACME_STAGING", None)
    if ACME_STAGING:
        Logger.warning("Using Let's Encrypt staging endpoint")
        ACME_DEFAULT_ENDPOINT = "https://acme-staging.api.letsencrypt.org/directory"
    else:
        ACME_DEFAULT_ENDPOINT = "https://acme-v01.api.letsencrypt.org/directory"
    ACME_ENDPOINT = os.getenv("ACME_ENDPOINT", ACME_DEFAULT_ENDPOINT)
    ACME_DIRECTORY = os.getenv("ACME_DIRECTORY", "/etc/ssl/private")
    DEFAULT_BACKEND = default_backend()

    def __init__(self):
        self.__acme = self.__get_client()

        challenges = self._file("acme-challenge")
        if not os.path.isdir(challenges):
            os.mkdir(challenges)

    def __openssl_to_crypto(self, key):
        pem = key.private_bytes(encoding=Encoding.PEM,
                                format=PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=NoEncryption())
        key = OpenSSL.crypto.load_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, pem)
        return key

    def _generate_ecdsa_key(self, curve="secp256r1", format="openssl"):
        Logger.debug("Generate an ECDSA private key, curve=%s", curve)
        curve_name = curve.lower()
        curve = ec._CURVE_TYPES.get(curve_name)
        if not curve:
            raise "Unsupported key curve: " + curve_name

        key = ACME.DEFAULT_BACKEND.generate_elliptic_curve_private_key(
            curve=curve())
        if format == "openssl":
            key = self.__openssl_to_crypto(key)
        return key

    def _generate_rsa_key(self, size=4096, exponent=65537, format="openssl"):
        Logger.debug("Generate a RSA private key, size=%d, exponent=%d", size,
                     exponent)
        key = ACME.DEFAULT_BACKEND.generate_rsa_private_key(key_size=size,
                                                            public_exponent=exponent)
        if format == "openssl":
            key = self.__openssl_to_crypto(key)
        return key

    def _save_key(self, key, file):
        if isinstance(key, OpenSSL.crypto.PKey):
            pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                                 key)
        else:
            pem = key.private_bytes(encoding=Encoding.PEM,
                                    format=PrivateFormat.TraditionalOpenSSL,
                                    encryption_algorithm=NoEncryption())
        with open(file, "wb") as file:
            file.write(pem)

    def _read_key(self, file, format="openssl"):
        with open(file, "rb") as file:
            pem = file.read()
        if format == "acme":
            key = ACME.DEFAULT_BACKEND.load_pem_private_key(data=pem,
                                                            password=None)
        else:
            key = OpenSSL.crypto.load_privatekey(
                type=OpenSSL.crypto.FILETYPE_PEM, buffer=pem, passphrase=None)
        return key

    def _generate_key(self, type="ecc", size="secp256r1", format="openssl"):
        if type == "rsa":
            return self.__generate_rsa_key(size, format=format)
        return self.__generate_ecdsa_key(size, format=format)

    def _save_csr(self, csr, file):
        pem = OpenSSL.crypto.dump_certificate_request(
            OpenSSL.crypto.FILETYPE_PEM, csr)
        with open(file, "wb") as file:
            file.write(pem)

    def _read_csr(self, file):
        with open(file, "rb") as file:
            pem = file.read()
        csr = OpenSSL.crypto.load_certificate_request(
            OpenSSL.crypto.FILETYPE_PEM, pem)
        return csr

    def _save_crt(self, crt, file):
        pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, crt)
        with open(file, "wb") as file:
            file.write(pem)

    def _read_crt(self, file):
        with open(file, "rb") as file:
            pem = file.read()
        crt = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, pem)
        return crt

    def _file(self, *path):
        return os.path.join(ACME.ACME_DIRECTORY, *path)

    def __create_client(self, key):
        key = josepy.JWKRSA(key=key)
        client = acme.client.Client(ACME.ACME_ENDPOINT, key)
        return client

    def __get_client(self):
        if ACME.ACME_STAGING:
            account_key = self._file("account-staging.pem")
        else:
            account_key = self._file("account.pem")

        if not os.path.isfile(account_key):
            Logger.info("Create new account key %s", account_key)
            key = self._generate_rsa_key(format="acme")
            self._save_key(key, account_key)

            client = self.__create_client(key)
            reg = client.register()
            Logger.info("Accept TOS: %s", reg.terms_of_service)
            client.agree_to_tos(reg)
        else:
            key = self._read_key(account_key, format="acme")
            client = self.__create_client(key)
        return client

    def __get_challenge(self, challenges, type=acme.challenges.HTTP01):
        challenges = challenges.body.challenges
        for body in challenges:
            challenge = body.chall
            if isinstance(challenge, type):
                return body, challenge
        raise Exception("Challenge %s not found" % type)

    def _pool_challenge(self, challenges, type=acme.challenges.HTTP01):
        for i in range(10):
            challenges, authzr_response = self.__acme.poll(challenges)
            body, challenge = self.__get_challenge(challenges, type=type)
            status = body.status

            Logger.debug("Challenge status: %s", status.name)
            if status == acme.messages.STATUS_INVALID:
                Logger.exception("Invalid challenge")
            elif status == acme.messages.STATUS_REVOKED:
                Logger.exception("Challenge revoked")
            elif status == acme.messages.STATUS_VALID:
                i = -1
                break

            sleep(1)
        if i > 0:
            Logger.exception("Challenge timeout")

        return challenges

    def __authorize_domain(self, domain):
        Logger.info("Validate %s", domain)
        challenges = self.__acme.request_domain_challenges(domain)
        body, challenge = self.__get_challenge(challenges)

        token = challenge.key_authorization(self.__acme.key)
        path = challenge.path
        url = challenge.uri(domain)

        path = self._file("acme-challenge", os.path.basename(path))
        with open(path, "w") as file:
            file.write(token)

        response = requests.get(url, verify=False)
        response.raise_for_status()
        retrieved = response.text

        if token != retrieved:
            Logger.exception(
                "Invalid token retrieved at %s: expected %s, got %s",
                url, token, retrieved)

        Logger.debug("Start validation")
        self.__acme.answer_challenge(body, body.response(self.__acme.key))
        challenges = self._pool_challenge(challenges)

        os.unlink(path)

        return challenges

    def __extract_san(self, x509):
        domain = set()

        if isinstance(x509, OpenSSL.crypto.X509):
            extensions = [x509.get_extension(i) for i in
                          range(x509.get_extension_count())]
        else:
            extensions = x509.get_extensions()

        for extension in extensions:
            if extension.get_short_name() == b"subjectAltName":
                san = extension.get_data()
                san = decoder.decode(san, asn1Spec=SubjectAltName())

                for name in san:
                    if isinstance(name, SubjectAltName):
                        for entry in range(len(name)):
                            component = name.getComponentByPosition(entry)
                            domain.add(str(component.getComponent()))
        return domain

    def _generate_csr(self, key, cn, domains=[]):
        if isinstance(domains, str):
            domains = [domains]
        domains = set(domains)
        domains.add(cn)
        Logger.info("Generate CSR for CN %s & SAN %s" % (cn, domains))

        x509_extensions = [
            OpenSSL.crypto.X509Extension(b"keyUsage", False,
                                         b"Digital Signature, Non Repudiation, Key Encipherment"),
            OpenSSL.crypto.X509Extension(b"basicConstraints", False,
                                         b"CA:FALSE")
        ]

        san = ",".join(["DNS: %s" % domain for domain in domains])
        san = OpenSSL.crypto.X509Extension(b"subjectAltName", False,
                                           san.encode())
        x509_extensions.append(san)

        req = OpenSSL.crypto.X509Req()
        req.get_subject().CN = cn
        req.add_extensions(x509_extensions)

        req.set_pubkey(key)
        req.sign(key, "sha512")

        return req

    def _extract_x509_domains(self, x509):
        cn = x509.get_subject().CN
        domains = self.__extract_san(x509)
        return cn, domains

    def _issue_certificate(self, csr):
        cn, domains = self._extract_x509_domains(csr)
        Logger.info("Issue certificate for %s", domains)
        auth = [self.__authorize_domain(domain) for domain in domains]

        Logger.info("Request issuance for %s", domains)
        chain = self.__acme.request_issuance(
            josepy.util.ComparableX509(csr), auth)

        Logger.info("Fetch certificate for %s", domains)
        crt = requests.get(chain.uri)
        crt.raise_for_status()
        crt = crt.content
        crt = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, crt)
        file = self._file("%s.crt" % cn)
        self._save_crt(crt, file)

        issuer = requests.get(chain.cert_chain_uri)
        issuer.raise_for_status()
        issuer = issuer.content
        issuer = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1,
                                                 issuer)
        issuer = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                 issuer)
        with open(file, "ab") as f:
            f.write(issuer)

        return crt

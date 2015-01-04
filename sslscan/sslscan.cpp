/***************************************************************************
 *   sslscan - A SSL cipher scanning tool                                  *
 *   Copyright (C) 2007-2008 by Ian Ventura-Whiting (Fizz)                 *
 *   fizz@titania.co.uk                                                    *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 3 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.  *
 *                                                                         *
 *   In addition, as a special exception, the copyright holders give       *
 *   permission to link the code of portions of this program with the      *
 *   OpenSSL library under certain conditions as described in each         *
 *   individual source file, and distribute linked combinations            *
 *   including the two.                                                    *
 *   You must obey the GNU General Public License in all respects          *
 *   for all of the code used other than OpenSSL.  If you modify           *
 *   file(s) with this exception, you may extend this exception to your    *
 *   version of the file(s), but you are not obligated to do so.  If you   *
 *   do not wish to do so, delete this exception statement from your       *
 *   version.  If you delete this exception statement from all source      *
 *   files in the program, then also delete it here.                       *
 ***************************************************************************/

// Force support of SSLv2 as we want to test if the server supports it
#define OPENSSL_NO_SSL2 0

// Includes...
#include <vector>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#if defined(MACHINE_CYGWIN)
#include <cygwin/in.h>
#endif
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <pwd.h>

#include "tclap/CmdLine.h"
using namespace TCLAP;
using namespace std;

#include "Version.h"
#include "Report.h"
#include "Section.h"
#include "Paragraph.h"
#include "Table.h"
#include "VisitorHTML.h"
#include "VisitorText.h"
#include "File.h"
#include "BoxDrawingCharacters.h"

#define ssl_all 0
#define ssl_v2 1
#define ssl_v3 2
#define tls_v1 3


const char *program_banner = "                   _\n"
                             "           ___ ___| |___  ___ __ _ _ __\n"
                             "          / __/ __| / __|/ __/ _` | '_ \\\n"
                             "          \\__ \\__ \\ \\__ \\ (_| (_| | | | |\n"
                             "          |___/___/_|___/\\___\\__,_|_| |_|\n\n"
                             "                    Version 2.0\n"
                             "              http://www.titania.co.uk\n"
                             "     Copyright (C) 2007-2008 Ian Ventura-Whiting\n"
                             "     Copyright (C) 2009-2015 Denis Dowling\n";
const char *program_version = "sslscan version 2.0\nhttp://www.titania.co.uk\nCopyright (C) 2007-2008 Ian Ventura-Whiting\nCopyright (C) 2009 Denis Dowling";
const char *xml_version = "2.1";


struct sslCipher
{
    // Cipher Properties...
    const char *name;
    char *version;
    int bits;
    const char *strength;
    char kx_str[20];
    char au_str[20];
    char enc_str[20];
    char mac_str[20];
    const SSL_METHOD *sslMethod;
    unsigned long cipher_id;
};
typedef vector<struct sslCipher> sslCipherVector;

struct sslCheckOptions
{
    // Program Options...
    bool debug;
    bool rejected;
    bool cipherInfo;
    bool starttls;
    int sslVersion;
    bool xout;
    bool istty;
    int screenWidth;
    bool assess_pci;

    string caBundle;

    // TCP Connection Variables...
    struct hostent *hostStruct;
    struct sockaddr_in serverAddress;

    sslCipherVector ciphers;
    string clientCertsFile;
    string privateKeyFile;
    string privateKeyPassword;
};

// FIXME Move to the main class when this exists
int num_pci_tests;
int num_pci_fails;

const char *getMethodStr(const SSL_METHOD *method)
{
#ifndef OPENSSL_NO_SSL2
    if (method == SSLv2_client_method())
	return "SSLv2";
    else
#endif
    if (method == SSLv3_client_method())
	return "SSLv3";
    else if (method == TLSv1_client_method())
	return "TLSv1";
    else
	return "Unknown SSL Method";
}

struct sslCipher *findCipher(struct sslCheckOptions *options,
			     const SSL_METHOD *method,
			     unsigned long id)
{
    sslCipherVector::iterator iter;
    for(iter = options->ciphers.begin();
	iter != options->ciphers.end();
	++iter)
    {
	struct sslCipher &p = *iter;

	if (p.cipher_id == id && p.sslMethod == method)
	    return &p;
    }

    return NULL;
}

const int PCI_MIN_RSA = 1024;
const int PCI_MIN_DSA = 1024;
const int PCI_MIN_SYMMETRIC = 128;

bool isPCIApprovedCipher(struct sslCipher *cipher)
{
    // Ciphers must be >= 128 bits
    if (cipher->bits < PCI_MIN_SYMMETRIC)
	return false;

    // Must be SSLv3 or TLS
    if (cipher->sslMethod != SSLv3_client_method() &&
	cipher->sslMethod != TLSv1_client_method())
	return false;

    // Must be able to authenticate the server
    if (strcmp(cipher->au_str, "None") == 0)
	return false;

    // FIXME This is the best definition I can find at the moment

    return true;
}

bool isPCIApprovedSignature(String algorithm_name)
{
    to_upper(algorithm_name);

    // MD5 and MD2 based signature algoritms do not cut it
    if (algorithm_name.find("SHA1") != string::npos)
	return true;
    else if (algorithm_name.find("SHA256") != string::npos)
	return true;
    else
	return false;
}

bool isPCIApprovedAlgorithm(String algorithm_name)
{
    if (algorithm_name == "rsaEncryption")
	return true;
    else if (algorithm_name == "dsaEncryption")
	return true;
    else
	// FIXME There are some other X509 algorithms that PCI are likely to approve
	return false;
}

void error(String s)
{
    s = String("ERROR: ") + s;

    String col_s = setTextColour(COL_RED, s);

    printf("%s", col_s.c_str());
}

// Adds Ciphers to the Cipher List structure
int populateCipherList(struct sslCheckOptions *options,
		       const SSL_METHOD *sslMethod)
{
    if (options->debug)
	printf("Populating cipher list for %s protocol version\n",
	       getMethodStr(sslMethod));

    // SSL Variables...
    SSL_CTX *ctx = SSL_CTX_new(sslMethod);
    if (ctx == NULL)
    {
	// Error Creating Context Object
	error("Could not create CTX object");
	return false;
    }

    if (options->debug)
	printf("Setting cipher list to all ciphers\n");

    SSL_CTX_set_cipher_list(ctx, "ALL:COMPLEMENTOFALL@STRENGTH");

    // Create new SSL object
    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
	error("Could not create SSL object.");
	ERR_print_errors_fp(stdout);
	return false;
    }

    // Get List of Ciphers
    STACK_OF(SSL_CIPHER) *cipherList;
    cipherList = SSL_get_ciphers(ssl);

    // Create Cipher Struct Entries...
    for (int loop = 0; loop < sk_SSL_CIPHER_num(cipherList); loop++)
    {
	SSL_CIPHER *cipher = sk_SSL_CIPHER_value(cipherList, loop);

	if (options->debug)
	    printf("cipher id=%ld\n"
		   "    algorithm_mkey=%lx\n"
		   "    algorithm_auth=%lx\n"
		   "    algorithm_enc=%lx\n"
		   "    algorithm_mac=%lx\n"
		   "    algorithm_ssl=%lx\n"
		   "    strength=%ld\n"
		   "    algorithm2=%ld\n"
		   "    strength_bits=%d\n"
		   "    alg_bits=%d\n\n",
		   cipher->id,
		   cipher->algorithm_mkey,
		   cipher->algorithm_auth,
		   cipher->algorithm_enc,
		   cipher->algorithm_mac,
		   cipher->algorithm_ssl,
		   cipher->algo_strength,
		   cipher->algorithm2,
		   cipher->strength_bits,
		   cipher->alg_bits);

	// Create Structure...
	options->ciphers.push_back(sslCipher());
	struct sslCipher *sslCipherPointer;
	sslCipherPointer = &(options->ciphers.back());

	// Init
	memset(sslCipherPointer, 0, sizeof(struct sslCipher));

	// Add cipher information...
	sslCipherPointer->sslMethod = sslMethod;
	sslCipherPointer->cipher_id = cipher->id;
	sslCipherPointer->name = SSL_CIPHER_get_name(cipher);
	sslCipherPointer->version = SSL_CIPHER_get_version(cipher);
	char description[512];
	SSL_CIPHER_description(cipher, description, sizeof(description) - 1);
	if (options->debug)
	    printf("description=%s\n", description);

	sscanf(description,
	       "%*s %*s %*3c%s %*3c%s %*4c%s %*4c%s",
	       sslCipherPointer->kx_str,
	       sslCipherPointer->au_str,
	       sslCipherPointer->enc_str,
	       sslCipherPointer->mac_str);

	// Strip the bits from enc
	char *p = strchr(sslCipherPointer->enc_str, '(');
	if (p != 0)
	    *p = '\0';

	if (options->debug)
	{
	    printf("kx_str=%s\n",
		   sslCipherPointer->kx_str);
	    printf("au_str=%s\n",
		   sslCipherPointer->au_str);
	    printf("enc_str=%s\n",
		   sslCipherPointer->enc_str);
	    printf("mac_str=%s\n",
		   sslCipherPointer->mac_str);
	}

	int tempInt;
	sslCipherPointer->bits = SSL_CIPHER_get_bits(cipher, &tempInt);
    }

    // Free SSL object
    SSL_free(ssl);

    const char *strengths[] = { "HIGH", "MEDIUM", "LOW", "EXPORT", "NULL" };
    for (const char **strength_p = strengths;
	 strength_p != strengths + sizeof(strengths)/sizeof(strengths[0]);
	 strength_p++)
    {
	if (options->debug)
	    printf("Setting cipher strength to %s\n", *strength_p);

	SSL_CTX_set_cipher_list(ctx, *strength_p);

	// Create new SSL object
	ssl = SSL_new(ctx);
	if (ssl == NULL)
	{
	    error("Could not create SSL object.:");
	    ERR_print_errors_fp(stdout);
	    printf("\n");
	    continue;
	}

	// Get List of Ciphers
	cipherList = SSL_get_ciphers(ssl);

	for (int loop = 0; loop < sk_SSL_CIPHER_num(cipherList); loop++)
	{
	    unsigned long id = sk_SSL_CIPHER_value(cipherList, loop)->id;
	    struct sslCipher *sslCipherPointer =
		findCipher(options, sslMethod, id);
	    if (sslCipherPointer != 0)
	    {
		if (sslCipherPointer->strength != NULL)
		{
		    StringStream err;
		    err << "Cipher "
			<< sslCipherPointer->name
			<< " has multiple strengths "
			<< sslCipherPointer->strength
			<< " and " << *strength_p;
		    error(err.str());
		}
		sslCipherPointer->strength = *strength_p;
	    }
	    else
	    {
		StringStream err;
		err << "Could not locate Cipher id " << id;
		error(err.str());
	    }
	}

	// Free SSL object
	SSL_free(ssl);
    }

    SSL_CTX_free(ctx);

    // Fill in strength for ciphers that don't have it defined
    sslCipherVector::iterator iter;
    for(iter = options->ciphers.begin();
	iter != options->ciphers.end();
	++iter)
    {
	struct sslCipher &p = *iter;

	if (p.strength == NULL)
	    p.strength = "(Unknown)";
    }

    return true;
}


// File Exists
int fileExists(char *fileName)
{
	// Variables...
	struct stat fileStats;

	if (stat(fileName, &fileStats) == 0)
		return true;
	else
		return false;
}


// Read a line from the input...
void readLine(FILE *input, char *lineFromFile, int maxSize)
{
	// Variables...
	int stripPointer;

	// Read line from file...
	fgets(lineFromFile, maxSize, input);

	// Clear the end-of-line stuff...
	stripPointer = strlen(lineFromFile) -1;
	while ((lineFromFile[stripPointer] == '\r') || (lineFromFile[stripPointer] == '\n') || (lineFromFile[stripPointer] == ' '))
	{
		lineFromFile[stripPointer] = 0;
		stripPointer--;
	}
}


// Create a TCP socket
int tcpConnect(string host, int port, struct sslCheckOptions *options)
{
    // Variables...
    int status;

    // Create Socket
    int socketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
    if(socketDescriptor < 0)
    {
	error("Could not open a socket");
	return 0;
    }

    // Connect
    status = connect(socketDescriptor, (struct sockaddr *) &options->serverAddress, sizeof(options->serverAddress));
    if(status < 0)
    {
	StringStream err;
	err << "Could not open a connection to host " << host
	    << " on port " << port;
	error(err.str());
	return 0;
    }

    // If STARTTLS is required...
    if (options->starttls)
    {
	const int buffer_size = 1024;
	unsigned char buffer[buffer_size];
	memset(buffer, 0, buffer_size);
	int len = recv(socketDescriptor, buffer, buffer_size - 1, 0);
	if (options->debug)
	    printf("Received %d characters:\n%s\n", len, buffer);

	if (memcmp(buffer, "220", 3) != 0)
	{
	    close(socketDescriptor);
	    StringStream err;
	    err << "The host " << host << " on port " << port
		<< " did not appear to be an SMTP service";
	    error(err.str());
	    return 0;
	}

	const char *ehlo = "EHLO opsol.com.au\r\n";
	send(socketDescriptor, ehlo, strlen(ehlo), 0);
	if (options->debug)
	    printf("Sent %ld characters:\n%s\n", strlen(ehlo), ehlo);

	memset(buffer, 0, buffer_size);
	len = recv(socketDescriptor, buffer, buffer_size - 1, 0);
	if (options->debug)
	    printf("Received %d characters:\n%s\n", len, buffer);

	if (memcmp(buffer, "250", 3) != 0)
	{
	    close(socketDescriptor);
	    StringStream err;
	    err << "The SMTP service on host " << host
		<< " port " << port
		<< " did not respond with status 250 to our HELO";
	    error(err.str());
	    return 0;
	}

	const char *starttls = "STARTTLS\r\n";
	send(socketDescriptor, starttls, strlen(starttls), 0);
	if (options->debug)
	    printf("Sent %ld characters:\n%s\n", strlen(starttls), starttls);

	memset(buffer, 0, buffer_size);
	len = recv(socketDescriptor, buffer, buffer_size - 1, 0);
	if (options->debug)
	    printf("Received %d characters:\n%s\n", len, buffer);

	if (memcmp(buffer, "220", 3) != 0)
	{
	    close(socketDescriptor);
	    StringStream err;
	    err << "The SMTP service on host " << host
		<< " port " << port
		<< " did not appear to support STARTTLS";
	    error(err.str());
	    return 0;
	}
    }

    // Return
    return socketDescriptor;
}


// Private Key Password Callback...
static int password_callback(char *buf, int size, int rwflag, void *userdata)
{
    strncpy(buf, (char *)userdata, size);
    buf[strlen((char *)userdata)] = '\0';
    return strlen((char *)userdata);
}


// Load client certificates/private keys...
int loadCerts(SSL_CTX *ctx, struct sslCheckOptions *options)
{
	// Variables...
	int status = 1;
	PKCS12 *pk12 = NULL;
	FILE *pk12File = NULL;
	X509 *cert = NULL;
	EVP_PKEY *pkey = NULL;
	STACK_OF(X509) *ca = NULL;

	// Configure PKey password...
	if (options->privateKeyPassword.size() > 0)
	{
		SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)options->privateKeyPassword.c_str());
		SSL_CTX_set_default_passwd_cb(ctx, password_callback);
	}

	// Seperate Certs and PKey Files...
	if ((options->clientCertsFile.size() > 0) && (options->privateKeyFile.size() > 0))
	{
		// Load Cert...
		if (!SSL_CTX_use_certificate_file(ctx, options->clientCertsFile.c_str(), SSL_FILETYPE_PEM))
		{
			if (!SSL_CTX_use_certificate_file(ctx, options->clientCertsFile.c_str(), SSL_FILETYPE_ASN1))
			{
				if (!SSL_CTX_use_certificate_chain_file(ctx, options->clientCertsFile.c_str()))
				{
				    error("Could not configure certificate(s)");
					status = 0;
				}
			}
		}

		// Load PKey...
		if (status != 0)
		{
			if (!SSL_CTX_use_PrivateKey_file(ctx, options->privateKeyFile.c_str(), SSL_FILETYPE_PEM))
			{
				if (!SSL_CTX_use_PrivateKey_file(ctx, options->privateKeyFile.c_str(), SSL_FILETYPE_ASN1))
				{
					if (!SSL_CTX_use_RSAPrivateKey_file(ctx, options->privateKeyFile.c_str(), SSL_FILETYPE_PEM))
					{
						if (!SSL_CTX_use_RSAPrivateKey_file(ctx, options->privateKeyFile.c_str(), SSL_FILETYPE_ASN1))
						{
						    error("Could not configure private key");
							status = 0;
						}
					}
				}
			}
		}
	}

	// PKCS Cert and PKey File...
	else if (options->privateKeyFile.size() > 0)
	{
		pk12File = fopen(options->privateKeyFile.c_str(), "rb");
		if (pk12File != NULL)
		{
			pk12 = d2i_PKCS12_fp(pk12File, NULL);
			if (!pk12)
			{
				status = 0;
				error("Could not read PKCS#12 file");
			}
			else
			{
				if (!PKCS12_parse(pk12, options->privateKeyPassword.c_str(), &pkey, &cert, &ca))
				{
					status = 0;
					error("Error parsing PKCS#12. Are you sure that password was correct?");
				}
				else
				{
					if (!SSL_CTX_use_certificate(ctx, cert))
					{
						status = 0;
						error("Could not configure certificate");
					}
					if (!SSL_CTX_use_PrivateKey(ctx, pkey))
					{
						status = 0;
						error("Could not configure private key");
					}
				}
				PKCS12_free(pk12);
			}
			fclose(pk12File);
		}
		else
		{
		    error("Could not open PKCS#12 file");
			status = 0;
		}
	}

	// Check Cert/Key...
	if (status != 0)
	{
		if (!SSL_CTX_check_private_key(ctx))
		{
		    error("Private key does not match certificate");
			return false;
		}
		else
			return true;
	}
	else
		return false;
}

void addPCICell(Table &t, bool pass)
{
    t.addCell(pass ? "PASS" : "FAIL");
    t.setCellColour(pass ? COL_GREEN : COL_RED);

    num_pci_tests++;
    if (!pass)
	num_pci_fails++;
}

// Test a cipher...
int testCipher(SSL_CTX *ctx, string host, int port, struct sslCheckOptions *options, struct sslCipher *sslCipherPointer, Table &table)
{
    // Variables...
    int cipherStatus;
    int status = true;
    SSL *ssl = NULL;
    BIO *cipherConnectionBio;

    if (options->debug)
	printf("Testing cipher %s\n", sslCipherPointer->name);

    // Connect to host
    int socketDescriptor = tcpConnect(host, port, options);
    if (socketDescriptor == 0)
    {
	// Could not connect
	return false;
    }

    if (SSL_CTX_set_cipher_list(ctx, sslCipherPointer->name) == 0)
    {
	close(socketDescriptor);

	error(String("Could set cipher ") + sslCipherPointer->name);
    }

    // Create SSL object...
    ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
	close(socketDescriptor);

	error("Could create SSL object");
	return false;
    }

    // Connect socket and BIO
    cipherConnectionBio = BIO_new_socket(socketDescriptor, BIO_NOCLOSE);

    // Connect SSL and BIO
    SSL_set_bio(ssl, cipherConnectionBio, cipherConnectionBio);

    // Connect SSL over socket
    cipherStatus = SSL_connect(ssl);

    // Disconnect SSL over socket
    if (cipherStatus == 1)
	SSL_shutdown(ssl);

    // Show Cipher Status
    if (options->rejected || cipherStatus == 1)
    {
	table.addRow();

	if (cipherStatus == 1)
	    table.addCell("Accepted");
	else if (cipherStatus == 0)
	    table.addCell("Rejected");
	else
	    table.addCell("Failed");

	table.addCell(getMethodStr(sslCipherPointer->sslMethod));
	table.addCell(sslCipherPointer->name);
	table.addCell(sslCipherPointer->strength);

	if (options->cipherInfo)
	{
	    table.addCell(sslCipherPointer->kx_str);
	    table.addCell(sslCipherPointer->au_str);
	    table.addCell(sslCipherPointer->enc_str);
        }
	char bits_str[30];
	sprintf(bits_str, "%d", sslCipherPointer->bits);
	table.addCell(bits_str);

	if (options->cipherInfo)
	{
	    table.addCell(sslCipherPointer->mac_str);
	}

	if (options->assess_pci)
	{
	    if (cipherStatus == 1)
		addPCICell(table, isPCIApprovedCipher(sslCipherPointer));
	    else
		table.addCell("");
	}

	// Free SSL object
	SSL_free(ssl);
    }

    // Disconnect from host
    close(socketDescriptor);

    return status;
}


// Test for preferred ciphers
int defaultCipher(string host, int port, struct sslCheckOptions *options,
		  const SSL_METHOD *sslMethod, Table &table)
{
    // Variables...
    int cipherStatus;
    int status = true;
    int socketDescriptor = 0;
    SSL *ssl = NULL;
    BIO *cipherConnectionBio;
    int tempInt2;

    // Connect to host
    socketDescriptor = tcpConnect(host, port, options);
    if (socketDescriptor != 0)
    {
	// Setup Context Object...
	SSL_CTX *ctx = SSL_CTX_new(sslMethod);
	if (ctx != NULL)
	{
	    if (SSL_CTX_set_cipher_list(ctx, "ALL:COMPLEMENTOFALL") != 0)
	    {
		// Load Certs if required...
		if ((options->clientCertsFile.size() > 0) || (options->privateKeyFile.size() > 0))
		    status = loadCerts(ctx, options);

		if (status == true)
		{
		    // Create SSL object...
		    ssl = SSL_new(ctx);
		    if (ssl != NULL)
		    {
			// Connect socket and BIO
			cipherConnectionBio = BIO_new_socket(socketDescriptor, BIO_NOCLOSE);

			// Connect SSL and BIO
			SSL_set_bio(ssl, cipherConnectionBio, cipherConnectionBio);

			// Connect SSL over socket
			cipherStatus = SSL_connect(ssl);
			if (cipherStatus == 1)
			{
			    table.addRow();

			    table.addCell(getMethodStr(sslMethod));

			    char buf[30];
			    sprintf(buf, "%d", SSL_get_cipher_bits(ssl, &tempInt2));
			    table.addCell(buf);

			    table.addCell(SSL_get_cipher_name(ssl));

			    if (options->assess_pci)
			    {
				const SSL_CIPHER *ssl_cipher =
				    SSL_get_current_cipher(ssl);
				struct sslCipher *sslCipherPointer =
				    findCipher(options,
					       sslMethod,
					       ssl_cipher->id);
				addPCICell(table,
					   sslCipherPointer != 0 &&
					   isPCIApprovedCipher(sslCipherPointer));
			    }

			    // Disconnect SSL over socket
			    SSL_shutdown(ssl);
			}

			// Free SSL object
			SSL_free(ssl);
		    }
		    else
		    {
			status = false;
			error("Could create SSL object");
		    }
		}
	    }
	    else
	    {
		status = false;
		error("Could set cipher");
	    }

	    // Free CTX Object
	    SSL_CTX_free(ctx);
	}

	// Error Creating Context Object
	else
	{
	    status = false;
	    error("Could not create CTX object");
	}

	// Disconnect from host
	close(socketDescriptor);
    }
    // Could not connect
    else
	status = false;

    return status;
}

void add_cert_row(Table &t, const String &name, const String &value)
{
    t.addRow();
    t.addCell(name);
    t.addCell(value);
}

String get_bio_string(BIO *bio)
{
    int n = BIO_ctrl_pending(bio);
    char *buf = new char[n+1];
    int l = BIO_read(bio, buf, n);

    String s(buf, l);

    delete[] buf;

    return s;
}

void add_cert_row(Table &t, const String &name, BIO *bio)
{
    t.addRow();
    t.addCell(name);
    t.addCell(get_bio_string(bio));
}

String getCN(X509 *cert)
{
    X509_NAME *name = X509_get_subject_name(cert);

    char buf[1024];
    X509_NAME_get_text_by_NID(name, NID_commonName, buf, sizeof(buf));

    String str = "CN=";
    str += buf;

    return str;
}


// Get certificate...
int getCertificate(Section &section, string host, int port,
		   struct sslCheckOptions *options)
{
    // Variables...
    int cipherStatus = 0;
    int status = true;
    int socketDescriptor = 0;
    SSL *ssl = NULL;
    BIO *cipherConnectionBio = NULL;
    char buffer[1024];

    // Connect to host
    socketDescriptor = tcpConnect(host, port, options);
    if (socketDescriptor == 0)
	return false;

    // Setup Context Object...
    const SSL_METHOD *sslMethod = SSLv23_method();
    SSL_CTX *ctx = SSL_CTX_new(sslMethod);
    if (ctx == NULL)
    {
	// Error Creating Context Object
	error("Could not create CTX object");

	// Disconnect from host
	close(socketDescriptor);

	return false;
    }

    if (options->caBundle.size() != 0)
    {
	// Load the CA file
	if (! SSL_CTX_load_verify_locations(ctx, options->caBundle.c_str(), 0))
	{
	    // Error Creating Context Object
	    error(String("Failed to load trusted CA certificates from ") +
		  options->caBundle);
	}
    }

    if (SSL_CTX_set_cipher_list(ctx, "ALL:COMPLEMENTOFALL") == 0)
    {
	error("Could set cipher");

	// Free CTX Object
	SSL_CTX_free(ctx);

	// Disconnect from host
	close(socketDescriptor);

	return false;
    }

    // Load Certs if required...
    if ((options->clientCertsFile.size() > 0) || (options->privateKeyFile.size() > 0))
	status = loadCerts(ctx, options);

    if (status == true)
    {
	// Create SSL object...
	ssl = SSL_new(ctx);
	if (ssl == NULL)
	{
	    status = false;
	    error("Could create SSL object");
	}
	else
	{
	    // Connect socket and BIO
	    cipherConnectionBio = BIO_new_socket(socketDescriptor, BIO_NOCLOSE);

	    // Connect SSL and BIO
	    SSL_set_bio(ssl, cipherConnectionBio, cipherConnectionBio);

	    // Connect SSL over socket
	    cipherStatus = SSL_connect(ssl);
	    if (cipherStatus == 1)
	    {
		// Setup BIO's
		BIO *bio = BIO_new(BIO_s_mem());

		Paragraph &p = section.addParagraph();
		p.setText("SSL Certificate:");

		Table &t = p.addTable();
		t.addHeadingRow();
		t.addCell("Name");
		t.addCell("Value");
		if (options->assess_pci)
		    t.addCell("PCI");

		X509 *x509Cert = SSL_get_peer_certificate(ssl);
		if (x509Cert != NULL)
		{
		    // Cert Version
		    if (!(X509_FLAG_COMPAT & X509_FLAG_NO_VERSION))
		    {
			StringStream ss;
			ss << X509_get_version(x509Cert);
			add_cert_row(t, "Version", ss.str());
		    }

		    // Cert Serial No.
		    if (!(X509_FLAG_COMPAT & X509_FLAG_NO_SERIAL))
		    {
			i2a_ASN1_INTEGER(bio, x509Cert->cert_info->serialNumber);
			add_cert_row(t, "Serial Number", bio);
		    }

		    // Signature Algo...
		    if (!(X509_FLAG_COMPAT & X509_FLAG_NO_SIGNAME))
		    {
			    i2a_ASN1_OBJECT(bio, (ASN1_OBJECT *)x509Cert->cert_info->signature->algorithm);
			    String sig = get_bio_string(bio);
			    add_cert_row(t, "Signature Algorithm", sig);

			    if (options->assess_pci)
				addPCICell(t, isPCIApprovedSignature(sig));
		    }
		    // SSL Certificate Issuer...
		    if (!(X509_FLAG_COMPAT & X509_FLAG_NO_ISSUER))
		    {
			X509_NAME_oneline(X509_get_issuer_name(x509Cert), buffer, sizeof(buffer) - 1);
			add_cert_row(t, "Issuer", buffer);
		    }

		    // Validity...
		    if (!(X509_FLAG_COMPAT & X509_FLAG_NO_VALIDITY))
		    {
			ASN1_TIME *start = X509_get_notBefore(x509Cert);
			ASN1_TIME_print(bio, start);
			add_cert_row(t, "Not valid before", bio);
			if (options->assess_pci)
			    addPCICell(t, X509_cmp_current_time(start) <= 0);

			ASN1_TIME *end = X509_get_notAfter(x509Cert);
			ASN1_TIME_print(bio, end);
			add_cert_row(t, "Not valid after", bio);
			if (options->assess_pci)
			    addPCICell(t, X509_cmp_current_time(end) >= 0);
		    }

		    // SSL Certificate Subject...
		    if (!(X509_FLAG_COMPAT & X509_FLAG_NO_SUBJECT))
		    {
			X509_NAME_oneline(X509_get_subject_name(x509Cert),
					  buffer, sizeof(buffer) - 1);
			add_cert_row(t, "Subject", buffer);
		    }

		    // Public Key Algorithm...
		    if (!(X509_FLAG_COMPAT & X509_FLAG_NO_PUBKEY))
		    {
			i2a_ASN1_OBJECT(bio, x509Cert->cert_info->key->algor->algorithm);
			String algo = get_bio_string(bio);
			add_cert_row(t, "Public Key Algorithm", algo);

			if (options->assess_pci)
			    addPCICell(t, isPCIApprovedAlgorithm(algo));

			// Public Key...
			EVP_PKEY *publicKey = X509_get_pubkey(x509Cert);
			if (publicKey == NULL)
			    printf("ERROR: Public Key: Could not load\n");
			else
			{
			    bool key_ok = false;

			    switch (publicKey->type)
			    {
			    case EVP_PKEY_RSA:
			    {
				RSA_print(bio, publicKey->pkey.rsa, 0);
				add_cert_row(t, "RSA Public Key", bio);

				if (RSA_size(publicKey->pkey.rsa) * 8 >= PCI_MIN_RSA)
				    key_ok = true;
				break;
			    }
			    case EVP_PKEY_DSA:
				DSA_print(bio, publicKey->pkey.dsa, 0);
				add_cert_row(t, "DSA Public Key", bio);

				if (DSA_size(publicKey->pkey.dsa) * 8 >= PCI_MIN_DSA)
				    key_ok = true;

				break;

#if !defined(OPENSSL_NO_EC)
			    case EVP_PKEY_EC:
				EC_KEY_print(bio, publicKey->pkey.ec, 0);
				add_cert_row(t, "EC Public Key", bio);

				// FIXME What size does PCI accept?
				break;
#endif
			    default:
				add_cert_row(t, "Public Key", "Unknown Type");
				break;
			    }

			    if (options->assess_pci)
				addPCICell(t, key_ok);

			    EVP_PKEY_free(publicKey);
			}
		    }

		    // X509 v3...
		    if (!(X509_FLAG_COMPAT & X509_FLAG_NO_EXTENSIONS))
		    {
			if (sk_X509_EXTENSION_num(x509Cert->cert_info->extensions) > 0)
			{
			    for (int i = 0;
				 i < sk_X509_EXTENSION_num(x509Cert->cert_info->extensions);
				 i++)
			    {
				// Get Extension...
				X509_EXTENSION *extension =
				    sk_X509_EXTENSION_value(x509Cert->cert_info->extensions, i);

				// Print Extension name...
				ASN1_OBJECT *asn1Object = X509_EXTENSION_get_object(extension);
				i2a_ASN1_OBJECT(bio, asn1Object);
				if (X509_EXTENSION_get_critical(extension))
				    BIO_printf(bio, ": critical");

				String name = get_bio_string(bio);

				// Print Extension value...
				if (!X509V3_EXT_print(bio, extension, X509_FLAG_COMPAT, 0))
				{
				    M_ASN1_OCTET_STRING_print(bio, extension->value);
				}
				String value = get_bio_string(bio);
				add_cert_row(t, name, value);
			    }
			}
		    }
		}

		String chain_str;
		STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
		for (int i = 0; i < sk_X509_num(chain); i++)
		{
		    X509 *cert = sk_X509_value(chain, i);
		    if (i != 0)
			chain_str += "\n";

		    chain_str += getCN(cert);
		}

		add_cert_row(t, "Certificate Chain", chain_str);

		// Verify Certificate...
		long verifyError = SSL_get_verify_result(ssl);
		if (verifyError == X509_V_OK)
		{
		    add_cert_row(t, "Verify Certificate",
				 "Certificate passed verification");

		    if (options->assess_pci)
			addPCICell(t, true);
		}
		else
		{
		    add_cert_row(t, "Verify Certificate",
				 X509_verify_cert_error_string(verifyError));

		    if (options->assess_pci)
			addPCICell(t, false);
		}

		// Free X509 Certificate...
		X509_free(x509Cert);

		// Free BIO
		BIO_free(bio);
	    }

	    // Disconnect SSL over socket
	    SSL_shutdown(ssl);
	}

	// Free SSL object
	SSL_free(ssl);
    }

    // Free CTX Object
    SSL_CTX_free(ctx);

    // Disconnect from host
    close(socketDescriptor);

    return status;
}


// Test a single host and port for ciphers...
int testHost(Report &report, string host, int port,
	     struct sslCheckOptions *options)
{
    // Variables...
    int status = true;

    // Resolve Host Name
    options->hostStruct = gethostbyname(host.c_str());
    if (options->hostStruct == NULL)
    {
	error(String("Could not resolve hostname " + host));
	return false;
    }

    // Configure Server Address and Port
    options->serverAddress.sin_family = options->hostStruct->h_addrtype;
    memcpy((char *) &options->serverAddress.sin_addr.s_addr, options->hostStruct->h_addr_list[0], options->hostStruct->h_length);
    options->serverAddress.sin_port = htons(port);

    Section &section = report.addSection();
    section.setHeading(String("Hostname ") + host);

    Paragraph &p = section.addParagraph();
    StringStream ss;
    ss << "Testing SSL server " << host << " on port " << port << ".";
    p.setText(ss.str());

    p = section.addParagraph();
    p.setText("Supported Server Ciphers:");

    Table &table = p.addTable();
    table.addHeadingRow();
    table.addCell("Status");
    table.addCell("Version");
    table.addCell("Cipher");
    table.addCell("Strength");
    if (options->cipherInfo)
    {
	table.addCell("Kx");
	table.addCell("Au");
	table.addCell("Enc");
    }
    table.addCell("Bits");
    if (options->cipherInfo)
    {
	table.addCell("Mac");
    }

    if (options->assess_pci)
	table.addCell("PCI");

    int total_ciphers = options->ciphers.size();
    int cur_cipher = 0;
    sslCipherVector::iterator iter;
    for(iter = options->ciphers.begin();
	iter != options->ciphers.end();
	++iter)
    {
	sslCipher &p = *iter;

	// Setup Context Object...
	SSL_CTX *ctx = SSL_CTX_new(p.sslMethod);
	if (ctx == NULL)
	{
	    // Error Creating Context Object
	    status = false;
	    error("Could not create CTX object");
	    continue;
	}

	// Load Certs if required...
	if ((options->clientCertsFile.size() > 0) || (options->privateKeyFile.size() > 0))
	    status = loadCerts(ctx, options);

	// Test
	if (status == true)
	    status = testCipher(ctx, host, port, options, &p, table);

	// Free CTX Object
	SSL_CTX_free(ctx);

	cur_cipher++;

	if (options->istty)
	{
	    String progress_str(cur_cipher % (options->screenWidth - 10), '.');
	    printf("\r%3d%% %s ",
		   cur_cipher * 100 / total_ciphers,
		   progress_str.c_str());
	    fflush(stdout);
	}
    }
    if (options->istty)
	printf("\n");

    if (status)
    {
	Paragraph &p = section.addParagraph();
	p.setText("Preferred Server Ciphers:");

	Table &table = p.addTable();
	table.addHeadingRow();
	table.addCell("Version");
	table.addCell("Bits");
	table.addCell("Cipher");
	if (options->assess_pci)
	    table.addCell("PCI");

	switch (options->sslVersion)
	{
	case ssl_all:
#ifndef OPENSSL_NO_SSL2
	    status = defaultCipher(host, port, options, SSLv2_client_method(), table);
#endif
	    status &= defaultCipher(host, port, options, SSLv3_client_method(), table);
	    status &= defaultCipher(host, port, options, TLSv1_client_method(), table);
	    break;
#ifndef OPENSSL_NO_SSL2
	case ssl_v2:
	    status = defaultCipher(host, port, options, SSLv2_client_method(), table);
	    break;
#endif
	case ssl_v3:
	    status = defaultCipher(host, port, options, SSLv3_client_method(), table);
	    break;
	case tls_v1:
	    status = defaultCipher(host, port, options, TLSv1_client_method(), table);
	    break;
	}
    }

//    if (status)
	status = getCertificate(section, host, port, options);

    // Return status...
    return status;
}


int main(int argc, char *argv[])
{
    // Variables...
    struct sslCheckOptions options;
    String output_file;
    vector<String> targets;

    try {
	CmdLine cmd("SSL Scanner", ' ', APP_VERSION);

	SwitchArg rejectedArg("r", "rejected", "Show rejected ciphers");
	cmd.add(rejectedArg);

	SwitchArg cipherArg("i", "cipher-info", "Show cipher information");
	cmd.add(cipherArg);

	SwitchArg htmlArg("x", "html", "Output HTML format");
	cmd.add(htmlArg);

	ValueArg<String> certsArg("c", "certs", "A file containing PEM/ASN1 formatted client certificates", false, "", "string");
	cmd.add(certsArg);

	ValueArg<String> outputArg("o", "output", "If this option is specified then all results will be written to this file", false, "", "string");
	cmd.add(outputArg);

	ValueArg<String> privateKeyArg("p", "pk", "A file containing the private key or a PKCS#12  file containing a private key/certificate pair", false, "", "string");
	cmd.add(privateKeyArg);

	ValueArg<String> privateKeyPasswordArg("", "pkpass", "The password for the private  key or PKCS#12 file", false, "", "string");
	cmd.add(privateKeyPasswordArg);

	SwitchArg startTlsArg("", "starttls", "Output a STARTTLS if it is required for an SMTP");
	cmd.add(startTlsArg);

	SwitchArg allArg("a", "all", "Check all SSL ciphers", true);
	SwitchArg sslv2Arg("", "ssl2", "Only check SSLv2 ciphers");
	SwitchArg sslv3Arg("", "ssl3", "Only check SSLv3 ciphers");
	SwitchArg tlsv1Arg("", "tls1", "Only check TLSv1 ciphers");

	vector<Arg*>  xorlist;
	xorlist.push_back(&allArg);
	xorlist.push_back(&sslv2Arg);
	xorlist.push_back(&sslv3Arg);
	xorlist.push_back(&tlsv1Arg);
	cmd.xorAdd(xorlist);

	SwitchArg debugArg("d", "debug", "Turn on program debugging");
	cmd.add(debugArg);

	ValueArg<String> charsetArg("C", "charset", "Terminal character set. Either ascii, msdos, utf8 to vt100. Used to switch on line drawing characters", false, "", "string");
	cmd.add(charsetArg);

	ValueArg<String> targetsFileArg("f", "file", "Read the scan targets from a file", false, "", "string");
	cmd.add(targetsFileArg);

	UnlabeledMultiArg<String> targetsArg("targets", "Targets to scan", false, "hostname:port");
	cmd.add(targetsArg);

	// Parse the args.
	cmd.parse( argc, argv );

	options.istty = isatty(1);
        output_file = outputArg.getValue();
#if defined(__WIN32__)
	setANSIColour(false);
#else
	setANSIColour(options.istty);
#endif
	if (charsetArg.getValue().size() > 0 &&
	    !setCodePageFromString(charsetArg.getValue()))
	{
	    cerr << "Illegal character set " << charsetArg.getValue() << endl;
	    return 1;
	}

	SSL_library_init();

	options.rejected = rejectedArg.getValue();
	options.cipherInfo = cipherArg.getValue();
	options.xout = htmlArg.getValue();
	options.clientCertsFile = certsArg.getValue();
	options.privateKeyFile = privateKeyArg.getValue();
	options.privateKeyPassword = privateKeyPasswordArg.getValue();
	options.starttls = startTlsArg.getValue();
	if (options.starttls)
	    options.sslVersion = tls_v1;

	if (sslv2Arg.getValue())
	    options.sslVersion = ssl_v2;
	else if (sslv3Arg.getValue())
	    options.sslVersion = ssl_v3;
	else if (tlsv1Arg.getValue())
	    options.sslVersion = tls_v1;
	else
	    options.sslVersion = ssl_all;

	options.debug = debugArg.getValue();

	// FIXME switchable
	options.assess_pci = true;
	options.screenWidth = 80;

	// FIXME switchable
	String ca_bundle_path =
	    ".:/etc/pki/tls/certs";
	options.caBundle = File::findOnPath(ca_bundle_path, "ca-bundle.crt");
	if (options.caBundle.size() == 0)
	{
	    error("Could not find the file ca-bundle.crt any any path " + ca_bundle_path);
	    return 1;
	}

	num_pci_tests = 0;
	num_pci_fails = 0;

        targets = targetsArg.getValue();

	string targets_file = targetsFileArg.getValue();
	if (targets_file.size() > 0)
	{
	    FILE *fd = fopen(targets_file.c_str(), "r");
	    if (fd == 0)
	    {
	        perror("Cannot open targets file");
		return 1;
	    }
	    while(!feof(fd))
	    {
	       	char line[1024]; 
		if (fgets(line, sizeof(line), fd) == 0)
		    break;

	        if (line[0] == '\0' || line[0] == '#')
		    continue;

		String s = line;
		s = trim(s);
		if (s.size() == 0)
		    continue;

		targets.push_back(s);
	    }
	}

	if (targets.size() == 0)
	{
	    cerr << "No targets specified" << endl;
	    return 1;
	}
    }
    catch (ArgException &e)  // catch any exceptions
    {
	cerr << "error: " << e.error() << " for arg " << e.argId() << endl;
	return 1;
    }

    cout << setTextColour(COL_BLUE, program_banner) << endl;

    Report report;
    report.setTitle("SSLScan Report");
    report.setAuthor("FIXME");

    SSLeay_add_all_algorithms();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    ERR_load_BIO_strings();

    // Build a list of ciphers...
    switch (options.sslVersion)
    {
    case ssl_all:
#ifndef OPENSSL_NO_SSL2
	populateCipherList(&options, SSLv2_client_method());
#endif
	populateCipherList(&options, SSLv3_client_method());
	populateCipherList(&options, TLSv1_client_method());
	break;
#ifndef OPENSSL_NO_SSL2
    case ssl_v2:
	populateCipherList(&options, SSLv2_client_method());
	break;
#endif
    case ssl_v3:
	populateCipherList(&options, SSLv3_client_method());
	break;
    case tls_v1:
	populateCipherList(&options, TLSv1_client_method());
	break;
    }

    time_t start_time;
    time(&start_time);

    if (1)
    {
	Section &header_section = report.addSection();
	header_section.setHeading("Header");

	char host[1024];
	if (gethostname(host, sizeof(host)) != 0)
	    strcpy(host, "Unknown");

	uid_t uid = getuid();
	struct passwd *passwd = getpwuid(uid);
	char username[1024];
	if (passwd != 0)
	    strcpy(username, passwd->pw_name);
	else
	    strcpy(username, "Unknown");

	Paragraph &p = header_section.addParagraph();
	p.setText(String(argv[0]) + " Results");

	Table &table = p.addTable();

	table.addRow();
	table.addCell("Copyright");
	table.addCell("Open Source Solutions Pty Ltd 2015");

	table.addRow();
	table.addCell("Version");
	table.addCell(String(APP_VERSION) + " (" + __DATE__ + " " + __TIME__ + ")");

	table.addRow();
	table.addCell("Started");
	table.addCell(ctime(&start_time));

	table.addRow();
	table.addCell("Username");
	table.addCell(username);

	table.addRow();
	table.addCell("Machine");
	table.addCell(host);

	table.addRow();
	table.addCell("Command");

	StringStream ss;
	for(int i = 0; i < argc; i++)
	    ss << argv[i] << " ";
	table.addCell(ss.str());
    }

    Table *host_table = 0;
    Section *summary_section = 0;
    // FIXME Flag to disable summary section?
    if (1)
    {
	summary_section = &report.addSection();
	summary_section->setHeading("Summary");

	StringStream ss;
	ss << "On "
	   << ctime(&start_time)
	   << " the SSL protocol responses on the following hosts"
	   << " were analysed:";
	Paragraph &p = summary_section->addParagraph();
	p.setText(ss.str());

	host_table = &p.addTable();
	host_table->addHeadingRow();
	host_table->addCell("Host");
	host_table->addCell("Port");
    }

    vector<String>::iterator iter;
    for (iter = targets.begin(); iter != targets.end(); ++iter)
    {
	string target = *iter;

	size_t i = target.find(':');
	string host;
	int port;
	if (i == string::npos)
	{
	    host = target;
	    port = 443;

	}
	else
	{
	    host = target.substr(0, i);
	    port = atoi(target.substr(i+1).c_str());
	}

	if (host_table != 0)
	{
	    host_table->addRow();
	    host_table->addCell(host);
	    StringStream ss;
	    ss << port;
	    host_table->addCell(ss.str());
	}

	testHost(report, host, port, &options);
    }

    if (summary_section != 0)
    {
	StringStream ss;
	ss << "The results for scanning the " << targets.size()
	   << " host" << (targets.size() != 1 ? "s" : "")
	   << " are shown below." << endl;
	Paragraph &p = summary_section->addParagraph();
	p.setText(ss.str());

	if (options.assess_pci)
	{
	    StringStream ss;
	    ss << "PCI DSS compliance testing was enabled for this SSL scan."
	       << " Overall the system was found to "
	       << (num_pci_fails == 0 ? "PASS" : "FAIL")
	       << " the PCI DSS compliance tests." << endl;
	    ss << "This utility assessed the SSL responses against "
	       << num_pci_tests << " separate PCI DSS tests and found that "
	       << num_pci_fails << " tests failed.";

	    Paragraph &p = summary_section->addParagraph();
	    p.setText(ss.str());
	}
    }

    FILE *output_fd = stdout;
    if (output_file.size() != 0)
    {
        output_fd = fopen(output_file.c_str(), "w");
	if (output_fd == 0)
	{
	    perror("Cannot open the output file");
	    return 1;
	}
    }

    if (options.xout)
    {
	VisitorHTML v;
	report.traverse(v);
	fprintf(output_fd, "%s", v.getHTML().c_str());
    }
    else
    {
	bool use_colour = (output_file.size() == 0);
	VisitorText v(use_colour);
	report.traverse(v);
	fprintf(output_fd, "%s", v.getText().c_str());
    }

    if (output_fd != stdout)
	fclose(output_fd);

    return 0;
}


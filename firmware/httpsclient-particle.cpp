/*
	This file follows client.c from matrixSSL-3.7.2b closely to make a post/
	get using https. It is also inspired by the httpclient library available
	on github for the particle photon
	(https://github.com/nmattisson/HttpClient)
 */
 // WARNING WARNING WARNING:
 // This is for test purposes only, the RSA keys included in header files are SAMPLE
 // If you use these keys in production, an attacker can de-crypt your data, and look
 // at it, and you might as well have been using http without https.

#include "httpsclient-particle.h"
#ifdef ID_RSA
#include "2048_RSA.h"
#include "2048_RSA_KEY.h"
#include "ALL_RSA_CAS.h"
#endif

int32_t sendHttpsRequest(std::string request);
int32_t processTCP(uint32_t numBytes);
int32_t processAppData(uint32_t bytes);
void processAlert(char alertLevel, char alertDescr);
int32_t writeRequestToTCP(std::string request);
int32_t sendToTCP();
uint32_t readFromTCP(unsigned long maxTime);
static int32_t certCb(ssl_t *ssl, psX509Cert_t *cert, int32_t alert);
static int32_t extensionCb(ssl_t *ssl, unsigned short extType, unsigned short extLen, void *e);

uint32_t
	freemem,
	g_cipher[1] = { TLS_RSA_WITH_AES_128_CBC_SHA256 },
// TODO: Complete HACK, is it necessary to know how many bytes to expect from
//       the server?
	g_bytes_requested = 100000;

int32_t
	rc,
	CAstreamLen,
	i,
	len,
	sessionFlag,
	extLen;

unsigned char
	*CAstream,
	*g_buf,
	*ext,
	*g_httpRequestHdr;

const int
	g_key_len = 2048,
	g_ciphers = 1;

const char
	end_header[] = "\r\n\r\n",
	*g_host,
	*g_path;

const uint32_t
	TIMEOUT = 4000;

sslKeys_t
	*keys;

sslSessionId_t
	*sid;

tlsExtension_t
	*extension;

ssl_t
	*ssl;

sslSessOpts_t
	options;

TCPClient
	tcpClient;

void printFreeMem()
{
	Serial.print("\tFree memory: ");
	Serial.println(System.freeMemory());
}

void httpsclientSetPath(const char * path)
{
	g_path = path;
}

int32_t httpsclientSetup(const char * host, const char * path)
{
	int32_t rc;
	g_host = host;
	g_path = path;

	if ((rc = matrixSslOpen()) != PS_SUCCESS)
	{
		Serial.println("\tMatrixSSL library init failure.");
		return rc;
	}

	if ((rc = matrixSslNewKeys(&keys, nullptr)) != PS_SUCCESS)
	{
		Serial.println("\tMatrixSSL library key init failure.");
		return rc;
	}

	CAstreamLen = 0;
	CAstreamLen += sizeof(RSACAS);

	if (CAstreamLen > 0)
		CAstream = (unsigned char *)malloc(CAstreamLen);
	else
		CAstream = nullptr;

	CAstreamLen = 0;

	memcpy(CAstream, RSACAS, sizeof(RSACAS));
	CAstreamLen += sizeof(RSACAS);

	Serial.println("Using 2048 bit RSA private key");

	/*	The keys parameter must be freed with matrixSslDeleteKeys after its
		useful life. */
	rc = matrixSslLoadRsaKeysMem(
		keys,               // I/O: Already allocated keys structure returned from a previous call to matrixSslNewKeys
		RSA2048,            // IN:  The X.509 ASN.1 identity certificate for this SSL peer.
		sizeof(RSA2048),    // IN:  Length of the RSA buffer
		RSA2048KEY,         // IN:  The PKCS#1 or PKCS#8 private RSA key that was used to sign the certBuf.
		sizeof(RSA2048KEY), // IN:  Length of the key buffer.
		CAstream,           // IN:  The X.509 ASN.1 stream of the trusted root certificates (Certificate Authorities) for this SSL peer.
		CAstreamLen         // IN:  Length of the CA stream.
	);

	options.ticketResumption = 0;
	options.maxFragLen       = 0;
	options.truncHmac        = 0;
	#ifdef USE_ECC
	options.ecFlags          = 0;
	#endif
	options.versionFlag      = SSL_FLAGS_TLS_1_2;
	options.userPtr          = nullptr;
	options.memAllocPtr      = nullptr;
	options.bufferPool       = nullptr;

	if (rc != PS_SUCCESS)
	{
		Serial.println("Keys didn't load!");
		return rc;
	}

	Serial.println("Keys Loaded");

	if (CAstream) free(CAstream);

	Serial.println("New session key.");

	return 0;
}

int32_t sendHttpsRequest(std::string request)
{
	Serial.println("HTTPS > sendHttpsRequest");
	printFreeMem();

	int32_t rc;

	Serial.println("HTTPS > sendHttpsRequest > Connecting TCPClient");
    if (!tcpClient.connect(g_host, 443))
    {
        tcpClient.stop();
    	Serial.print("HTTPS > sendHttpsRequest > ");
        Serial.print("The client failed to connect to ");
        Serial.print(g_host);
        Serial.println();
        return -1;
    }

	/*	The sid parameter must be freed with matrixSslDeleteSessionId after its
		useful life. The poolUserPtr value will be passed as the userPtr to
		psOpenPool when creating the dedicated memory pool for the session
		material. */
	rc = matrixSslNewSessionId(
		&sid,   // I/O: Storage for an SSL session ID used to resume sessions.
		nullptr // IN:  Optional allocation context.
	);
	Serial.print("HTTPS > sendHttpsRequest > matrixSslNewSessionId=");
	Serial.println(rc);
	if (rc < 0)
	{
		return rc;
	}

	/*	The user must free tlsExtension_t with matrixSslDeleteHelloExtension
		after the useful life. The extension data is internally copied into the
		CLIENT_HELLO message during the call to matrixSslNewClientSession so
		matrixSslDeleteHelloExtension may be called immediately after
		matrixSslNewClientSession if the user does not require further use. */
	rc = matrixSslNewHelloExtension(
		&extension, // OUT: Newly allocated tlsExtension_t structure to be used as input to matrixSslLoadHelloExtension
		nullptr     // IN:  Optional allocation context
	);
	Serial.print("HTTPS > sendHttpsRequest > matrixSslNewHelloExtension=");
	Serial.println(rc);
	if (rc < 0)
	{
		return rc;
	}

	/*	The application should free the returned extOut memory buffer after the
		call to matrixSslLoadHelloExtension since that function will copy the
		data internally. */
	rc = matrixSslCreateSNIext(
		nullptr,                  // IN:  Optional allocation context
		(unsigned char*)g_host,   // IN:  The hostname to format
		(uint32_t)strlen(g_host), // IN:  The length of the hostname
		&ext,                     // OUT: Newly allocated SNI extension buffer
		&extLen                   // OUT: The length of the allocated buffer.
	);
	Serial.print("HTTPS > sendHttpsRequest > matrixSslCreateSNIext=");
	Serial.println(rc);
	if (rc < 0)
	{
		return rc;
	}

	/*	The extData memory is internally copied into the extension structure so
		the caller may immediately free extData upon return from this
		function. */
	rc = matrixSslLoadHelloExtension(
		extension, // IN:  Allocated tlsExtension_t struct
		ext,       // IN:  Fully encoded hello extension for the CLIENT_HELLO
		extLen,    // IN:  The length of the hello extension
		EXT_SNI    // IN:  Standardized extension type
	);
	Serial.print("HTTPS > sendHttpsRequest > matrixSslLoadHelloExtension=");
	Serial.println(rc);
	if (rc < 0)
	{
		return rc;
	}

	if (ext) free(ext);

	/*	The user must free the ssl_t structure using matrixSslDeleteSession
		after the useful life of the session. The caller does not need to free
		the ssl parameter if this function does not return
		MATRIXSSL_REQUEST_SEND. The keys pointer is referenced in the ssl_t
		context without duplication so it is essential the user does not call
		matrixSslDeleteKeys until all associated sessions have been deleted. */
	rc = matrixSslNewClientSession(
		&ssl,        // I/O: The new context for the SSL Session
		keys,        // IN:  The pointer to the certificate and keys
		nullptr,     // I/O: The session ID storage allocated by matrixSslNewSessionId
		g_cipher,    // IN:  The cipher suite(s) to use
		g_ciphers,   // IN:  The number of cipher suite(s)
		certCb,      // IN:  Callback function to inspect the provided server certs
		nullptr,     // IN:  The expected name of the server we're trying to connect to
		extension,   // IN:  Custom CLIENT_HELLO extensions
		extensionCb, // IN:  Callback function to inspect the SERVER_HELLO
		&options     // IN:  Runtime options for SSL protocol version, max fragment length, etc.
	);
	Serial.print("HTTPS > sendHttpsRequest > matrixSslNewClientSession=");
	Serial.println(rc);
	if (rc < 0)
	{
		return rc;
	}

	matrixSslDeleteHelloExtension(extension);

	uint32_t msgLen;
	uint32_t readBytes = 0;

	// MatrixSSL has prepared a handshake for us, so send it.
	Serial.println("HTTPS > sendHttpsRequest > Sending handshake to peer.");
	printFreeMem();
	rc = sendToTCP();
	if (rc == PS_SUCCESS)
	{
		Serial.println("HTTPS > sendHttpsRequest > Reading handshake response.");
		printFreeMem();
		readBytes = readFromTCP(10000);

		Serial.println("HTTPS > sendHttpsRequest > Processing response.");
		printFreeMem();
		rc = processTCP(readBytes);
	}
	else
	{
		Serial.println("HTTPS > sendHttpsRequest > Error sending to TCP.");
		return rc;
	}

	if (rc == MATRIXSSL_HANDSHAKE_COMPLETE)
	{
		// If the handshake is done, then we can fire off the request.
		Serial.println("HTTPS > sendHttpsRequest > Sending HTTP request.");
		printFreeMem();
		rc = writeRequestToTCP(request);
	}
	else
	{
		Serial.println("HTTPS > sendHttpsRequest > Error processing TCP response.");
		return rc;
	}

	if (rc == PS_SUCCESS)
	{
		// Wait for a response to our request
		Serial.println("HTTPS > sendHttpsRequest > Reading request response.");
		printFreeMem();
		readBytes = readFromTCP(10000);
	}
	else
	{
		Serial.println("HTTPS > sendHttpsRequest > Error sending the request to TCP.");
		return rc;
	}

	// We should have recieved a response to our request, so process it.
	Serial.println("HTTPS > sendHttpsRequest > Processing response.");
	printFreeMem();
	rc = processTCP(readBytes);

	// Close the connection and clean up.
	Serial.println("HTTPS > sendHttpsRequest > Cleaning up.");
	printFreeMem();

	matrixSslEncodeClosureAlert(ssl);
	sendToTCP();

	matrixSslDeleteSessionId(sid);
	matrixSslDeleteSession(ssl);

    tcpClient.flush();
    tcpClient.stop();

	printFreeMem();
	return rc;
}

int32_t processTCP(uint32_t numBytes)
{
	Serial.println("HTTPS > processTCP");

	uint32_t msgLen, bytes;
	int32_t rc = matrixSslReceivedData(ssl, numBytes, &g_buf, &msgLen);

	switch (rc)
	{
	case MATRIXSSL_REQUEST_SEND:
		Serial.println("HTTPS > processTCP > MATRIXSSL_REQUEST_SEND");
		/*	Success. The processing of the received data resulted in an SSL
			response message that needs to be sent to the peer. If this return
			code is hit the user should call matrixSslGetOutdata to retrieve the
			encoded outgoing data. */
		sendToTCP();
		// Flow through to recieve messages.

	case MATRIXSSL_REQUEST_RECV:
		Serial.println("HTTPS > processTCP > MATRIXSSL_REQUEST_RECV");
		/*	Success. More data must be received and this function must be called
			again. User must first call matrixSslGetReadbuf again to receive the
			updated buffer pointer and length to where the remaining data should
			be read into. */
		bytes = readFromTCP(10000);
		return processTCP(bytes);

	case MATRIXSSL_HANDSHAKE_COMPLETE:
		Serial.println("HTTPS > processTCP > MATRIXSSL_HANDSHAKE_COMPLETE");
		/*	Success. The SSL handshake is complete. This return code is returned
			to client side implementation during a full handshake after parsing
			the FINISHED message from the server. It is possible for a server to
			receive this value if a resumed handshake is being performed where
			the client sends the final FINISHED message. */
		return rc;

	case MATRIXSSL_RECEIVED_ALERT:
		Serial.println("HTTPS > processTCP > MATRIXSSL_RECEIVED_ALERT");
		/*	Success. The data that was processed was an SSL alert message. In
			this case, the ptbuf pointer will be two bytes (ptLen will be 2) in
			which the first byte will be the alert level and the second byte
			Will be the alert description. After examining the alert, the user
			must call matrixSslProcessedData to indicate the alert was processed
			and the data may be internally discarded. */
		processAlert(g_buf[0], g_buf[1]);
		return processAppData(msgLen);

	case MATRIXSSL_APP_DATA:
		Serial.println("HTTPS > processTCP > MATRIXSSL_APP_DATA");
		/*	Success. The data that was processed was application data that the
			user should process. In this return code case the ptbuf and ptLen
			output parameters will be valid. The user may process the data
			directly from ptbuf or copy it aside for later processing. After
			handling the data the user must call matrixSslProcessedData to
			indicate the plain text data may be internally discarded */
		// Flow through to compressed data.

	case MATRIXSSL_APP_DATA_COMPRESSED:
		Serial.println("HTTPS > processTCP > MATRIXSSL_APP_DATA_COMPRESSED");
		/*	Success. The application data that is returned needs to be inflated
			with zlib before being processed. This return code is only possible
			if the USE_ZLIB_COMPRESSION define has been enabled and the peer has
			agreed to compression. Compression is not advised due to TLS
			attacks. */
		return processAppData(msgLen);

	case PS_SUCCESS:
		Serial.println("HTTPS > processTCP > PS_SUCCESS");
		/*	Success. This return code will be returned if the bytes parameter is
			0 and there is no remaining internal data to process. This could be
			useful as a polling mechanism to confirm the internal buffer is
			empty. One real life usecase for this method of invocation is when
			dealing with a Google Chrome browser that uses False Start. */
		return rc;

	default:
		Serial.println("HTTPS > processTCP > DEFAULT");
		/*	Failure */
		Serial.print("Processing failure. Code=");
		Serial.println(rc);
		return rc;
	}
}

int32_t processAppData(uint32_t bytesToRead)
{
	Serial.println("HTTPS > processAppData");

	char decodedMsg[bytesToRead];
	Serial.println("Buffer contents:");
	for (size_t i = 0; i < bytesToRead; ++i)
		decodedMsg[i] = g_buf[i];
	Serial.println(decodedMsg);

	uint32_t msgLen = 0;
	uint32_t bytes;
	int32_t rc = matrixSslProcessedData(ssl, &g_buf, &msgLen);

	switch (rc)
	{
	case PS_SUCCESS:
		Serial.println("HTTPS > processAppData > PS_SUCCESS");
		/*	Success. This indicates that there are no additional records in the
			data buffer that require processing. The application protocol is
			responsible for deciding the next course of action. */
		return rc;

	case MATRIXSSL_APP_DATA:
		Serial.println("HTTPS > processAppData > MATRIXSSL_APP_DATA");
		/*	Success. There is a second application data record in the buffer
			that has been decoded. In this return code case the ptbuf and ptlen
			output parameters will be valid. The user may process the data
			directly from ptbuf or copy it aside for later processing. After
			handling the data the user must call matrixSslProcessedData again to
			indicate the plain text data may be internally discarded. */
		return processAppData(msgLen);

	case MATRIXSSL_REQUEST_SEND:
		Serial.println("HTTPS > processAppData > MATRIXSSL_REQUEST_SEND");
		/*	Success. This return code is possible if the buffer contained an
			application record followed by a SSL handshake message to initiate a
			re-handshake (CLIENT_HELLO or HELLO_REQUEST). In this case the SSL
			re-handshake response has been encoded and is waiting to be sent */
		sendToTCP();
		// Flow through to recieve messages.

	case MATRIXSSL_REQUEST_RECV:
		Serial.println("HTTPS > processAppData > MATRIXSSL_REQUEST_RECV");
		/*	Success. This return code is possible if there is a partial second
			record that follows in the buffer. Data storage must be retrieved
			via matrixSslGetReadbuf and passed through the matrixSslReceivedData
			call again. */
		bytes = readFromTCP(10000);
		return processTCP(bytes);

	case MATRIXSSL_RECEIVED_ALERT:
		Serial.println("HTTPS > processAppData > MATRIXSSL_RECEIVED_ALERT");
		/*	Success. There is a second record in the data buffer that is an SSL
			alert message. In this case, the ptbuf pointer will be two bytes
			(ptlen will be 2) in which the first byte will be the alert level
			and the second byte will be the alert description. After examining
			the alert, the user must call matrixSslProcessedData again to
			indicate the alert was processed and the data may be internally
			discarded. */
		processAlert(g_buf[0], g_buf[1]);
		return processAppData(msgLen);
	}
}

void processAlert(char alertLevel, char alertDescr)
{
	Serial.println("HTTPS > processAlert");
}

int32_t writeRequestToTCP(std::string request)
{
	Serial.println("HTTPS > writeRequestToTCP");

	int32_t rc = 0;

	Serial.println("Request:");
	Serial.println(request.c_str());

	rc = matrixSslEncodeToOutdata(ssl, (unsigned char *)const_cast<char *>(request.c_str()), request.length());

	return sendToTCP();
}

int32_t sendToTCP()
{
	Serial.println("HTTPS > sendToTCP");

	int32_t  bytesToSend = 0;
	uint32_t bytesSent   = 0;
	int32_t  rc          = 0;

	// Get the buffer to send from MatrixSSL
	bytesToSend = matrixSslGetOutdata(ssl, &g_buf);

	// Ship it!
	bytesSent = tcpClient.write(g_buf, bytesToSend);

	Serial.print("HTTPS > sendToTCP > Wrote ");
	Serial.print(bytesSent);
	Serial.print(" bytes to TCP.");
	Serial.println();

	// Inform MatrixSSL that we've sent some data.
	rc = matrixSslSentData(ssl, bytesSent);
	switch (rc)
	{
		case MATRIXSSL_REQUEST_SEND:
			Serial.println("HTTPS > sendToTCP > MATRIXSSL_REQUEST_SEND");
			/*	Success. Call matrixSslGetOutdata again and send more data to
				the peer. Indicates the number of bytes sent was not the full
				amount of pending data. */
			return sendToTCP();

		case MATRIXSSL_REQUEST_CLOSE:
			Serial.println("HTTPS > sendToTCP > MATRIXSSL_REQUEST_CLOSE");
			/*	Success. This indicates the message that was sent to the peer
				was an alert and the caller should close the session. */
			//return closeSslSession();
			return rc;

		case MATRIXSSL_HANDSHAKE_COMPLETE:
			Serial.println("HTTPS > sendToTCP > MATRIXSSL_HANDSHAKE_COMPLETE");
			/*	Success. Will be returned to the peer if this is the final
				FINISHED message that is being sent to complete the
				handshake. */
			return rc;

		case PS_SUCCESS:
			Serial.println("HTTPS > sendToTCP > PS_SUCCESS");
			// Success, no more data to send.
			return rc;

		case PS_ARG_FAIL:
			Serial.println("HTTPS > sendToTCP > PS_ARG_FAIL");
			// Failure. Bad input parameters.
			return rc;

		default:
			Serial.println("HTTPS > sendToTCP > DEFAULT");
			return rc;
	}
}

uint32_t readFromTCP(unsigned long maxTime)
{
	Serial.println("HTTPS > readFromTCP");

	int32_t  availableBytes;
	uint32_t buffPosition = 0;

	if((availableBytes = matrixSslGetReadbuf(ssl, &g_buf)) < 1)
		return 0;

	unsigned long started = millis();

	do
	{
		while(tcpClient.available())
		{
			char c = tcpClient.read();
			g_buf[buffPosition++] = c;

			if (buffPosition == availableBytes)
			{
				Serial.println("HTTPS > readFromTCP > Read maximum bytes.");
				Serial.print("HTTPS > readFromTCP > Read bytes:");
				Serial.println(buffPosition);
				return buffPosition;
			}
		}

	} while (tcpClient.connected() && millis() - started < maxTime && buffPosition == 0);

	Serial.print("HTTPS > readFromTCP > Read bytes:");
	Serial.println(buffPosition);
	return buffPosition;
}

static int32_t certCb(ssl_t *ssl, psX509Cert_t *cert, int32_t alert)
{
	Serial.println("HTTPS > certCb");
	psX509Cert_t *next;

	// Did we even find a CA that issued the certificate?
	if (alert == SSL_ALERT_UNKNOWN_CA)
	{
		// Example to allow anonymous connections based on a define
		if (ALLOW_ANON_CONNECTIONS)
		{
			Serial.print("HTTPS > certCb > Allowing anonymous connection for:");
			Serial.println(cert->subject.commonName);
			return SSL_ALLOW_ANON_CONNECTION;
		}

		Serial.print("HTTPS > certCb > ERROR: No matching CA found. Terminating connection.");
	}

	/*	If the expectedName passed to matrixSslNewClientSession does not match
		any of the server subject name or subjAltNames, we will have the alert
		below. For security, the expected name (typically a domain name) _must_
		match one of the certificate subject names, or the connection should not
		continue. The default MatrixSSL certificates use localhost and 127.0.0.1
		as the subjects, so unless the server IP matches one of those, this
		alert will happen. To temporarily disable the subjet name validation,
		NULL can be passed as expectedName to matrixNewClientSession. */
	if (alert == SSL_ALERT_CERTIFICATE_UNKNOWN)
	{
		Serial.print("HTTPS > certCb > ERROR: Expected name was not found in cert subject names - ");
		Serial.println(ssl->expectedName);
	}

	if (alert == SSL_ALERT_CERTIFICATE_EXPIRED)
	{
		#ifdef POSIX
			Serial.println("HTTPS > certCb > ERROR: A cert did not fall within the notBefore/notAfter window.");
		#else
			Serial.println("HTTPS > certCb > WARNING: Certificate date window validation not implemented.");
			alert = 0;
		#endif
	}

	if (alert == SSL_ALERT_ILLEGAL_PARAMETER)
	{
		Serial.println("HTTPS > certCb > ERROR: Found correct CA but X.509 extension details are wrong.");
	}

	// Key usage related problems on chain
	for (next = cert; next != nullptr; next = next->next)
	{
		if (next->authStatus == PS_CERT_AUTH_FAIL_EXTENSION)
		{
			if (next->authFailFlags & PS_CERT_AUTH_FAIL_KEY_USAGE_FLAG)
				Serial.println("HTTPS > certCb > CA keyUsage extension doesn't allow cert signing.");

			if (next->authFailFlags & PS_CERT_AUTH_FAIL_EKU_FLAG)
				Serial.println("HTTPS > certCb > Cert extendedKeyUsage extension doesn't allow TLS.");
		}
	}

	if (alert == SSL_ALERT_BAD_CERTIFICATE)
	{
		/*	Should never let a connection happen if this is set. There was
			either a problem in the presented chain or in the final CA test */
		Serial.println("HTTPS > certCb > ERROR: Problem in certificate validation. Exiting.");
	}

	if (alert == 0)
	{
		Serial.print("HTTPS > certCb > SUCCESS: Validated cert for ");
		Serial.println(cert->subject.commonName);
	}

	return alert;
}

static int32_t extensionCb(ssl_t *ssl, unsigned short extType, unsigned short extLen, void *e)
{
	Serial.println("HTTPS > extensionCb");

	unsigned char *c;
	short         len;
	char          proto[128];

	c = (unsigned char*) e;

	if (extType == EXT_ALPN)
	{
		memset(proto, 0x0, 128);
		// two byte proto list len, one byte proto len, then proto
		c += 2; // Skip proto list len
		len = *c; c++;
		memcpy(proto, c, len);
		Serial.print("HTTPS > extensionCb > Server agreed to use ");
		Serial.println(proto);
	}

	return PS_SUCCESS;
}
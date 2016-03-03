package grails.plugin.mail

import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security
import java.security.cert.Certificate
import java.security.cert.X509Certificate

import javax.security.auth.x500.*;

import org.bouncycastle.util.Store;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.smime.*
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.mail.smime.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.util.Strings;
import org.bouncycastle.asn1.x509.*;

import org.slf4j.Logger
import org.slf4j.LoggerFactory


import javax.activation.CommandMap
import javax.activation.MailcapCommandMap
import javax.mail.internet.*;
import javax.mail.*;

class MailSecurityHelper {

	private static final Logger log = LoggerFactory.getLogger(MailSecurityHelper.class)

	// setups the mail command map
	static setMailCommandMap(){

		// Add BouncyCastle content handlers to command map
		MailcapCommandMap mailcap = (MailcapCommandMap) CommandMap.getDefaultCommandMap();

		mailcap.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
		//mailcap.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.superman.mail.smime.handlers.pkcs7_signature");

		mailcap.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
		//mailcap.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.superman.mail.smime.handlers.pkcs7_mime");

		mailcap.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
		//mailcap.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.superman.mail.smime.handlers.x_pkcs7_signature");

		mailcap.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
		//mailcap.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.superman.mail.smime.handlers.x_pkcs7_mime");

		mailcap.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");
		//mailcap.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.superman.mail.smime.handlers.multipart_signed");

		CommandMap.setDefaultCommandMap(mailcap);
	}


	// builds the mail capabilities
	static buildCapabilities(){

		SMIMECapabilityVector capabilities = new SMIMECapabilityVector();

		capabilities.addCapability(SMIMECapability.dES_EDE3_CBC);
		capabilities.addCapability(SMIMECapability.rC2_CBC, 128);
		capabilities.addCapability(SMIMECapability.dES_CBC);
		capabilities.addCapability(SMIMECapability.aES256_CBC);
		capabilities.addCapability(SMIMECapability.aES128_CBC);
		capabilities.addCapability(SMIMECapability.aES192_CBC);

		capabilities
	}

	// configures the signing vector
	static getSignedAttributes(serialNumber){

		def capabilities = buildCapabilities()

		ASN1EncodableVector signedAttrs = new ASN1EncodableVector();
		signedAttrs.add(new SMIMEEncryptionKeyPreferenceAttribute(serialNumber));
		signedAttrs.add(new SMIMECapabilitiesAttribute(capabilities));

		signedAttrs
	}


	// Provide location of Java Keystore and password for access
	// Handles .p12, .pfx files, all other extensions are assumed to be jks format
	static getKeyStore(keyStoreLocation, keyStorePassword){

		//TODO - should be moved somewhere in the plugin init, for now is good enough here
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		KeyStore keyStore = null;

		if(keyStoreLocation.endsWith('.p12') || keyStoreLocation.endsWith('.pfx')){
			keyStore = KeyStore.getInstance("PKCS12", "BC");
		}else{
			keyStore = KeyStore.getInstance("JKS");
		}

		InputStream ins = new FileInputStream(keyStoreLocation);

		// Provide location of Java Keystore and password for access
		keyStore.load(ins,keyStorePassword.toCharArray());

		keyStore
	}
	
	// loads a private key from a keyStore
	static getPrivateKey(keyStore, alias, keyPassword){
		
		KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(keyPassword.toCharArray()));
		PrivateKey privateKey = pkEntry.getPrivateKey();

		privateKey
	}

	// extract key aliases(names) from a store
	static getKeyAliases(keyStore){

		// Find the first legit alias in the keystore and use it
		Enumeration<String> es = keyStore.aliases();

		def aliases = [];
		while (es.hasMoreElements()) {
			def alias = es.nextElement();

			// Does alias refer to a private key? Assign true/false
			if (keyStore.isKeyEntry(alias) && alias) {
				aliases.add(alias)
			}
		}

		aliases
	}

	// Builds a bouncycastle JcaCertStore from a java keystore
	static buildCertStore(keyStore, alias){
		def cert =  keyStore.getCertificate(alias);
		Store certs = new JcaCertStore(Arrays.asList(cert));
	}

	// gets the FIRST issuer from keyStore cert chain
	static getIssuer(keyStore, alias){
		// Load certificate chain
		Certificate[] chain = keyStore.getCertificateChain(alias);
		X509Certificate issuer = (X509Certificate) chain[0];
	}

	// get the issuer and serial number for a corresponding alias(name)
	static getIssuerAndSerialNumber(keyStore, alias){

		X509Certificate issuer = getIssuer(keyStore, alias)

		//Cert info
		X500Name x500 = new X500Name(issuer.getIssuerX500Principal().getName());

		IssuerAndSerialNumber serialNumber = new IssuerAndSerialNumber(x500 , issuer.getSerialNumber()) ;

		return serialNumber
	}

	// builds the signing generator, those are for now not cached
	static getSMIMEGenerator(keyStore, alias, keyPassword){

		PrivateKey privateKey = getPrivateKey(keyStore, alias, keyPassword)

		IssuerAndSerialNumber serialNumber = getIssuerAndSerialNumber(keyStore, alias)

		ASN1EncodableVector signedAttrs = getSignedAttributes(serialNumber)

		Store certStore = buildCertStore(keyStore,alias)

		//Signing generator
		SMIMESignedGenerator generator = new SMIMESignedGenerator();

		def jssigb = new JcaSimpleSignerInfoGeneratorBuilder()
				.setProvider("BC")
				.setSignedAttributeGenerator(new AttributeTable(signedAttrs))
				.build("SHA1withRSA", privateKey, keyStore.getCertificate(alias))

		generator.addSignerInfoGenerator(jssigb);
		generator.addCertificates(certStore);

		generator
	}

	// does the actual signing, log a warn if the key was not found
	static sign(session, msg, keyStore, alias, keyPassword){

		MimeMessage tmpMessage = msg;

		if(getKeyAliases(keyStore).find{it == alias}){

			tmpMessage = new MimeMessage(session);
			
			setMailCommandMap()

			def gen = getSMIMEGenerator(keyStore, alias, keyPassword)
			//Sign
			MimeMultipart mainPart = gen.generate(msg , "BC");

			/* Set all original MIME headers in the signed message */
			Enumeration headers = msg.getAllHeaderLines();
			while (headers.hasMoreElements())
			{
				tmpMessage.addHeaderLine((String)headers.nextElement());
			}

			// Set the content of the signed message
			tmpMessage.setContent(mainPart, mainPart.getContentType());
			tmpMessage.saveChanges();

		}else{
			log.warn "Cannot locate alias: ${alias} in keystore: ${keyStore}, skip signing ..."
		}

		return tmpMessage
	}

	// builds the encryption(envelope) generator, those are for now not cached
	static getSMIMEEnvelopedGenerator(keyStore, alias){
		SMIMEEnvelopedGenerator generator = new SMIMEEnvelopedGenerator();

		generator.addKeyTransRecipient(getIssuer(keyStore, alias));

		return generator
	}

	// does the actual encryption, log a warn if the key was not found
	static encrypt(session, msg, keyStore, alias){

		def generator = getSMIMEEnvelopedGenerator(keyStore, alias)

		MimeBodyPart mimeBodyPart = generator.generate(msg, SMIMEEnvelopedGenerator.RC2_CBC, "BC");

		/*
		 * Create a new MimeMessage that contains the encrypted and signed
		 * content
		 */
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		mimeBodyPart.writeTo(out);

		MimeMessage encryptedMessage = new MimeMessage(session,
				new ByteArrayInputStream(out.toByteArray()));

		/* Set all original MIME headers in the encrypted message */
		def headers = msg.getAllHeaderLines();
		while (headers.hasMoreElements())
		{
			String headerLine = (String)headers.nextElement();
			/*
			 * Make sure not to override any content-* headers from the
			 * original message
			 */
			if (!Strings.toLowerCase(headerLine).startsWith("content-")){
				encryptedMessage.addHeaderLine(headerLine);
			}else{
				log.debug "Skipping header line: ${headerLine}"
			}
		}

		encryptedMessage
	}

}


import java.io.*;
import java.net.*;
import java.util.*;
import java.util.Arrays;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

class server_java_tcp{
    
    public static KeyPair keyPairMaker() throws NoSuchAlgorithmException{
	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	keyGen.initialize(2048);
	return keyGen.genKeyPair();
    }
    
    public static byte[] encryption(byte[] plainbyte, byte[] key) 
	throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException{
	SecretKeySpec SKS = new SecretKeySpec(key, "AES");
	Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	cipher.init(Cipher.ENCRYPT_MODE, SKS);
	byte[] result = cipher.doFinal(plainbyte);
	return result;
    }
    
    public static String decryption (byte[] cipherbyte, byte[] key) 
	throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException{
	SecretKeySpec SKS = new SecretKeySpec(key, "AES");
	Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	cipher.init(Cipher.DECRYPT_MODE, SKS);
	byte[] result = cipher.doFinal(cipherbyte);
	return new String(result);
    }
    
    public static void main(String argv[]) throws Exception{
	
	int portNum, cipherKeySize, readIndex, nameSize, uuid, messageSize, sentenceSize;
	String welcomeMessage, line, name, clientName, clientSentence;	
	byte choice;
	byte[] sessionKey, RSABytes, cipherKey, nameBytes, cipherName, cipherMessage, sentenceBytes;			
	HashMap<Integer,String> dictionary;
	LinkedList<String> userNames, userMessages;
	LinkedList<byte[]> userKeys;
	ServerSocket welcomeSocket;
	KeyPair keyPair;
	BufferedReader welcomeReader;
	Socket connectionSocket;
	DataInputStream inFromClient;
	DataOutputStream outToClient;
	Cipher cipher;
	
	if(argv.length != 1){
	    //err 1
	    System.out.println("java server_java_tcp portNumber < welcomeMessage.txt");
	    System.exit(1);
	}
	
	portNum = Integer.parseInt(argv[0]);
	
	if( portNum < 1024 || portNum > 65535 ){
	    //err 2
	    System.out.println("Invalid port. Terminating.");
	    System.exit(1);
	}
	
	welcomeSocket = null;
	try{
	    welcomeSocket = new ServerSocket(portNum);
	}catch(IOException e){
	    //err 4
	    System.out.println("Could not bind port. Terminating.");
	    System.exit(1);
	}
			
	welcomeReader = new BufferedReader(new InputStreamReader(System.in));
	welcomeMessage = "";
	while((line = welcomeReader.readLine()) != null){
	    welcomeMessage += (line + '\n');
	}
	
	welcomeMessage = welcomeMessage.substring(0,welcomeMessage.length()-1);
	dictionary = new HashMap<Integer,String>();
	userNames = new LinkedList<String>();
	userMessages = new LinkedList<String>();
	userKeys = new LinkedList<byte[]>();
	sessionKey = null;
	
	while(true) {
	    
	    connectionSocket = welcomeSocket.accept();
	    
	    inFromClient = new DataInputStream
		(connectionSocket.getInputStream());
	    outToClient = new DataOutputStream
		(connectionSocket.getOutputStream());
	    
	    while(true){
		try{
		    choice = inFromClient.readByte();
		}catch(EOFException eof){
		    break;
		}
		switch(choice){
		case 1:
		    {
			keyPair = keyPairMaker();
			RSABytes = keyPair.getPublic().getEncoded();
			outToClient.writeInt(RSABytes.length);
			outToClient.write(RSABytes,0,RSABytes.length);
			cipherKeySize = inFromClient.readInt();
			cipherKey = new byte[cipherKeySize];
			readIndex = 0;
			
			while(readIndex<cipherKeySize){
			    readIndex += inFromClient.read(cipherKey,readIndex,cipherKeySize-readIndex);
			}
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
			sessionKey = cipher.doFinal(cipherKey);
			
			try{
			    nameSize = inFromClient.readInt();
			}catch(EOFException eof){break;}
			nameBytes = new byte[nameSize];
			
			readIndex= 0;
			while(readIndex<nameSize){
			    readIndex += inFromClient.read(nameBytes,readIndex,nameSize-readIndex);
			}
			
			name = new String(nameBytes);
			uuid = (new Random()).nextInt();
			dictionary.put(uuid,name);
			outToClient.writeByte(2);
			outToClient.writeInt(uuid);
			outToClient.writeByte(5);
			readIndex = 0;
			messageSize = welcomeMessage.length();
			outToClient.writeInt(messageSize);
			outToClient.writeBytes(welcomeMessage);
			break;
		    }
		    
		case 3:
		    {
			outToClient.writeByte(5);
			outToClient.writeInt(userMessages.size());
			for(int i = 0;i < userMessages.size();i++){
			    cipherName = encryption(userNames.get(i).getBytes(), sessionKey);
			    outToClient.writeInt(cipherName.length);
			    outToClient.write(cipherName,0,cipherName.length);
			    
			    cipherMessage = encryption(userMessages.get(i).getBytes(), sessionKey);
			    outToClient.writeInt(cipherMessage.length);
			    outToClient.write(cipherMessage,0,cipherMessage.length);
			}
			break;
		    }
		case 4:
		    {
			//sentence
			sentenceSize = inFromClient.readInt();
			sentenceBytes = new byte[sentenceSize];
			readIndex = 0;
			while(readIndex<sentenceSize){
			    readIndex += inFromClient.read(sentenceBytes,readIndex,sentenceSize-readIndex);
			}	    
			clientSentence = decryption(sentenceBytes,sessionKey);
			
			//name
			sentenceSize = inFromClient.readInt();
			sentenceBytes = new byte[sentenceSize];
			readIndex = 0;
			while(readIndex<sentenceSize){
			    readIndex += inFromClient.read(sentenceBytes,readIndex,sentenceSize-readIndex);
			}	    
			clientName = decryption(sentenceBytes,sessionKey);
			userNames.add(clientName);
			userMessages.add(clientSentence);
			break;			
		    }
		}
	    }
	}
    }
}

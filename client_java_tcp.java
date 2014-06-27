import java.lang.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.Arrays;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.X509EncodedKeySpec;



class client_java_tcp {  

    public static byte[] makeKey() throws NoSuchAlgorithmException{
	
	KeyGenerator keyMaker = KeyGenerator.getInstance("AES");
	SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
	keyMaker.init(128,random);
	SecretKey secretKey = keyMaker.generateKey();
	return secretKey.getEncoded(); 
    }
    
    public static byte[] encryption(byte[] plainBytes, byte[] key) 
	throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException{
	SecretKeySpec SKS = new SecretKeySpec(key, "AES");
	Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	cipher.init(Cipher.ENCRYPT_MODE, SKS);
	byte[] result = cipher.doFinal(plainBytes);
	return result;
    }
    
    public static String decryption (byte[] cipherBytes, byte[] key) 
	throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException{
	SecretKeySpec SKS = new SecretKeySpec(key, "AES");
	Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	cipher.init(Cipher.DECRYPT_MODE, SKS);
	byte[] decipheredBytes = cipher.doFinal(cipherBytes);
	return new String(decipheredBytes);
    }
   
    
    public static void main(String argv[]) throws Exception{
	
	int uuid, portNum, publicKeySize, readIndex, messageSize, nameSize, messageListSize;
	String IPAddress, command, sentence, ciphertext, user, strName, modifiedSentence;
	byte[] cipherbytes, sessionKey, publicKeyBytes, cipherKey, messageBytes, name;
	Socket clientSocket = null;
	BufferedReader inFromUser;
	DataOutputStream outToServer;
	DataInputStream inFromServer;
	PublicKey publicKey;
	Cipher cipher;
	
	if(argv.length != 3){
	    //err 1
	    System.out.println("java client_java_tcp IPAddress portNumber userName");
	    System.exit(1);
	}
	
	portNum = Integer.parseInt(argv[1]);
	
	if( portNum < 1024 || portNum > 65535 ){
	    //err 2
	    System.out.println("Invalid port. Terminating.");
	    System.exit(1);
	}
	
	IPAddress = argv[0];
	
	try{
	    clientSocket = new Socket(IPAddress,portNum);
	}catch(IOException e){
	    //err 3
	    System.out.println("Could not connect to server. Terminating.");
	    System.exit(1);
	}
        
	inFromUser = new BufferedReader(new InputStreamReader(System.in));
	outToServer = new DataOutputStream(clientSocket.getOutputStream());
	inFromServer = new DataInputStream(clientSocket.getInputStream());
	outToServer.writeByte(1);
	
	sessionKey = makeKey();
	publicKeySize = inFromServer.readInt();
	publicKeyBytes = new byte[publicKeySize];
	
	readIndex = 0;
	while(readIndex < publicKeySize){
	    readIndex += inFromServer.read(publicKeyBytes,readIndex,publicKeySize-readIndex);
	}
	publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
	
	cipher = Cipher.getInstance("RSA");
	cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	cipherKey = cipher.doFinal(sessionKey);
	
	outToServer.writeInt(cipherKey.length);
	outToServer.write(cipherKey,0,cipherKey.length);
	
	user = argv[2];
	outToServer.writeInt(user.length());
	outToServer.writeBytes(user);
	
	if(inFromServer.readByte() != 2){
	    //err 5
	    System.out.println("Invalid server initialization. Terminating.");
	    System.exit(1);
	}else{
	    uuid = inFromServer.readInt();
	}
	
	if(inFromServer.readByte() != 5){
	    //err 5
	    System.out.println("Invalid server initialization. Terminating.");
	    System.exit(1);  
	}
	
	messageSize = inFromServer.readInt();
	
	messageBytes = new byte[messageSize];
	readIndex = 0;
	while(readIndex<messageSize){
	    readIndex += inFromServer.read(messageBytes,readIndex,messageSize-readIndex);
	}
        
	
	System.out.println("Welcome message: " + new String(messageBytes));
	modifiedSentence = "";
	while(true){
	    System.out.println("Enter a command: (send, print, or exit)");	
	    command = inFromUser.readLine();
	    
	    if(command.equals("send")){
		System.out.println("Enter your message:");	    
		sentence = inFromUser.readLine();
		outToServer.writeByte(4);
		cipherbytes = encryption(sentence.getBytes(), sessionKey);
		outToServer.writeInt(cipherbytes.length);
		outToServer.write(cipherbytes,0,cipherbytes.length);
		cipherbytes = encryption(user.getBytes(), sessionKey);
		outToServer.writeInt(cipherbytes.length);
		outToServer.write(cipherbytes,0,cipherbytes.length);
	    }
	    else if(command.equals("print")){
		outToServer.writeByte(3);
		if(inFromServer.readByte() != 5){
		    //err 6
		    System.out.println("Invalid packet from server. Terminating.");
		    System.exit(1);  
		}
		
		
		messageListSize = inFromServer.readInt();
		
		for(int i = 0;i < messageListSize;i++){
		    nameSize = inFromServer.readInt();
		    name = new byte[nameSize];
		    readIndex = 0;
		    while(readIndex < nameSize){
			readIndex += inFromServer.read(name,readIndex,nameSize-readIndex);
		    }  
		    
		    strName = decryption(name,sessionKey);
		    
		    modifiedSentence = strName + ": ";
		    messageSize = inFromServer.readInt();
		    messageBytes = new byte[messageSize];
		    readIndex = 0;
		    while(readIndex < messageSize){
			readIndex += inFromServer.read(messageBytes,readIndex,messageSize-readIndex);
		    }  
		    
		    modifiedSentence += (decryption(messageBytes,sessionKey));
		    System.out.println(modifiedSentence);
		}		
	    }
	    else if(command.equals("exit")){
		clientSocket.close();
		return;
	    }
	}
    }
}

// Author: 

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.SealedObject;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;
//import java.util.Base64.Decoder;

/************************************************
* This skeleton program is prepared for weak  *
* and average students.                       *
* If you are very strong in programming. DIY! *
* Feel free to modify this program.           *
***********************************************/

// Amy knows Bryan's public key
// Amy sends Bryan session (AES) key
// Amy receives messages from Bryan, decrypts and saves them to file

class Amy {  // Amy is a TCP client
  
  String bryanIP;  // ip address of bryan
  int bryanPort;   // port Bryan listens to
  Socket connectionSkt;  // socket used to talk to Bryan
  private ObjectOutputStream toBryan;   // to send session key to Bryan
  private ObjectInputStream fromBryan;  // to read encrypted messages from Bryan
  private Crypto crypto;        // object for encryption and decryption
  PublicKey pubKey;
  // file to store received and decrypted messages
  public static final String MESSAGE_FILE = "msgs.txt";
  
  public static void main(String[] args) {
    
    // Check if the number of command line argument is 2
    if (args.length != 2) {
      System.err.println("Usage: java Amy bryanIP BryanPort");
      System.exit(1);
    }
    
    new Amy(args[0], args[1]);
  }
  
  // Constructor
  public Amy(String ipStr, String portStr) {
    
    this.crypto = new Crypto();
    
    this.bryanIP = ipStr;
    this.bryanPort = Integer.parseInt(portStr);
    
    try {
      this.connectionSkt =  new Socket(this.bryanIP, this.bryanPort);
      this.toBryan = new ObjectOutputStream(this.connectionSkt.getOutputStream());
      this.fromBryan = new ObjectInputStream(this.connectionSkt.getInputStream());
    } catch (IOException ioe) {
      System.out.println("Error: cannot get input/output streams");
      System.exit(1);
    }
    
    // Receive public key sent by Bryan
    if(receivePublicKey())
    {
      System.out.println("MD5 signature matches - Using the verified public key now");
      sendSessionKey();  
    }else{
      System.out.println("Error:MD5 signature does not match");
      System.exit(1);
    }
    // Send session key to Bryan
    
    System.out.println("Start receiving messages now.");
    try{
      PrintWriter out = new PrintWriter(MESSAGE_FILE);
      while(true){
        receiveMessages(out);
      }
    } catch(Exception ex){
      ex.printStackTrace();
    }
  }
  
  // Receive public key from Bryan
  public boolean receivePublicKey() {
    
    boolean notCorrupt = false;
    
    try{
      
      this.pubKey = (PublicKey)this.fromBryan.readObject();
      byte[] digest = (byte[])this.fromBryan.readObject();
      byte[] decryptedDigest = this.crypto.decryptDigest(digest);
      
      byte[] public_key = this.pubKey.getEncoded();
      byte[] name = "bryan".getBytes(StandardCharsets.US_ASCII);
      
      MessageDigest md5 = MessageDigest.getInstance("MD5");
      md5.update(name);
      md5.update(public_key);
      byte[] checkDigest = md5.digest();
      
      if (Arrays.equals(decryptedDigest,checkDigest)){
        notCorrupt = true;
      }else{
        notCorrupt = false;
      }
      
    } catch (IOException ioe) {
      System.out.println("IO Exception Occured.");
      System.exit(1);
    } catch (ClassNotFoundException ioe) {
      System.out.println("Error: cannot typecast to class SealedObject");
      System.exit(1); 
    } catch (NoSuchAlgorithmException ex){
      System.out.println("No Such Algor Exception Thrown");
      System.exit(1);
    }
    return notCorrupt;
  }
  
  // Send session key to Bryan
  public void sendSessionKey() {
    try {
      
      SealedObject encryptedMsg = this.crypto.getSessionKey(this.pubKey);
      this.toBryan.writeObject(encryptedMsg);
      
      System.out.println("Session Key sent to Bryan");
      
    } catch (Exception ex) {
      System.out.println("Error sending messages to Bryan");
      System.exit(1);
    }
  }
  
  // Receive messages one by one from Bryan, decrypt and write to file
  public void receiveMessages(PrintWriter out) {
    try {
      SealedObject sessionKeyObj = (SealedObject)this.fromBryan.readObject();
      String toWrite = this.crypto.decryptMsg(sessionKeyObj)+"\n";
      // System.out.print(toWrite);
      out.write(toWrite);
    } catch (IOException ioe) {
      // System.out.println("Error receiving session key from Bryan");
      System.out.println("Write Ended");
      out.close();
      System.exit(1);
    } catch (ClassNotFoundException ioe) {
      System.out.println("Error: cannot typecast to class SealedObject");
      System.exit(1); 
    }
  }
  
  /*****************/
  /** inner class **/
  /*****************/
  class Crypto {
    
    // Bryan's public key, to be read from file
    private PublicKey pubKey;
    private PublicKey berisignPubKey;
    // Amy generates a new session key for each communication session
    private SecretKey sessionKey;
    // File that contains Bryan' public key
    public static final String PUBLIC_KEY_FILE = "bryan.pub";
    public static final String BERISIGN_PUBLIC_KEY_FILE = "berisign.pub";
    
    // Constructor
    public Crypto() {
      // Read Bryan's public key from file
      readBerisignPublicKey();
      // Generate session key dynamically
      initSessionKey();
    }
    
    // Read Bryan's public key from file
    public void readBerisignPublicKey() {
      
      try {
        ObjectInputStream ois = 
        new ObjectInputStream(new FileInputStream(BERISIGN_PUBLIC_KEY_FILE));
        this.berisignPubKey = (PublicKey)ois.readObject();
        System.out.println("Reading Berisign Public Key");
        ois.close();
      } catch (IOException oie) {
        System.out.println("Error reading public key from file");
        System.exit(1);
      } catch (ClassNotFoundException cnfe) {
        System.out.println("Error: cannot typecast to class PublicKey");
        System.exit(1);
      }
      
      System.out.println("Berisign Public key read from file " + BERISIGN_PUBLIC_KEY_FILE);
      // key is stored as an object and need to be read using ObjectInputStream.
      // See how Bryan read his private key as an example.
    }
    
    // Generate a session key
    public void initSessionKey() {
      try{
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); 
        this.sessionKey = keyGen.generateKey();
      }catch(Exception ex){
        ex.printStackTrace();
      }
      // suggested AES key length is 128 bits
    }
    
    // Seal session key with RSA public key in a SealedObject and return
    public SealedObject getSessionKey(PublicKey pubKey) {
      
      SealedObject sessionKeyObj = null;
      this.pubKey = pubKey;
      
      try {
        // Amy must use the same RSA key/transformation as Bryan specified
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, this.pubKey);
        byte[] rawKey = this.sessionKey.getEncoded();
        sessionKeyObj = new SealedObject(rawKey, cipher);
        
        // RSA imposes size restriction on the object being encrypted (117 bytes).
        // Instead of sealing a Key object which is way over the size restriction,
        // we shall encrypt AES key in its byte format (using getEncoded() method).    
      } catch (GeneralSecurityException gse) {
        gse.printStackTrace();
        System.out.println("stuck session?");
        System.out.println("Error: wrong cipher to DECRYPT_MODE message");
        System.exit(1);
      } catch (IOException ioe) {
        System.out.println("Error creating SealedObject");
        System.exit(1);
      }
      
      return sessionKeyObj;       
    }
    
    public byte[] decryptDigest(byte[] digest){
      
      byte[] decryptedDigest = digest;
      
      try{           
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); 
        //System.out.println(this.berisignPubKey.toString());
        cipher.init(Cipher.DECRYPT_MODE, this.berisignPubKey);
        
        decryptedDigest = cipher.doFinal(digest);
      } catch (GeneralSecurityException gse) {
        System.out.println("Error: wrong cipher to decrypt message");
        gse.printStackTrace();
        System.exit(1);
      } catch (Exception ex) {
        ex.printStackTrace();
      }
      
      return  decryptedDigest;
    }
    
    // Decrypt and extract a message from SealedObject
    public String decryptMsg(SealedObject encryptedMsgObj) {
      
      String plainText = null;
      
      // Amy and Bryan use the same AES key/transformation
      try{
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.sessionKey);
        plainText = (String)encryptedMsgObj.getObject(cipher);
        
      } catch (GeneralSecurityException gse) {
        System.out.println("Error: wrong cipher to encrypt message");
        System.exit(1);
      } catch (IOException ioe) {
        System.out.println("Error creating SealedObject");
        System.exit(1);
      } catch (Exception ex) {
        ex.printStackTrace();
      }
      
      return plainText;
    }
    
  }
}
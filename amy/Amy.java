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
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.SealedObject;

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
    
    // Send session key to Bryan
    sendSessionKey();
    
    // Receive encrypted messages from Bryan,
    // decrypt and save them to file
    try{
      PrintWriter out = new PrintWriter(MESSAGE_FILE);
      while(true){
        receiveMessages(out);
      }
    } catch(Exception ex){
      ex.printStackTrace();
    }
  }
  
  // Send session key to Bryan
  public void sendSessionKey() {
    try {
      
      SealedObject encryptedMsg = this.crypto.getSessionKey();
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
      System.out.println("IO Exception - Write Ended");
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
    // Amy generates a new session key for each communication session
    private SecretKey sessionKey;
    // File that contains Bryan' public key
    public static final String PUBLIC_KEY_FILE = "bryan.pub";
    
    // Constructor
    public Crypto() {
      // Read Bryan's public key from file
      readPublicKey();
      // Generate session key dynamically
      initSessionKey();
    }
    
    // Read Bryan's public key from file
    public void readPublicKey() {
      
      try {
        ObjectInputStream ois = 
        new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
        this.pubKey = (PublicKey)ois.readObject();
        ois.close();
      } catch (IOException oie) {
        System.out.println("Error reading public key from file");
        System.exit(1);
      } catch (ClassNotFoundException cnfe) {
        System.out.println("Error: cannot typecast to class PublicKey");
        System.exit(1);
      }
      
      System.out.println("Public key read from file " + PUBLIC_KEY_FILE);
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
    public SealedObject getSessionKey() {
      
      SealedObject sessionKeyObj = null;
      
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
        System.out.println("Error: wrong cipher to encrypt message");
        System.exit(1);
      } catch (IOException ioe) {
        System.out.println("Error creating SealedObject");
        System.exit(1);
      }
      
      return sessionKeyObj;       
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
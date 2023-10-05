import java.math.BigInteger;
import java.math.BigInteger;
import java.util.*;
import java.math.*;
import java.security.*;
import java.time.Duration;
import java.time.Instant;
import java.lang.Object;
import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;

public class DH_Key_Exchange {

	
	private static BigInteger p=new BigInteger("50702342087986984684596540672785294493370824085308498450535565701730450879745310594069460940052367603038103747343106687981163754506284021184158903198888031001641800021787453760919626851704381009545624331468658731255109995186698602388616345118779571212089090418972317301933821327897539692633740906524461904910061687459642285855052275274576089050579224477511686171168825003847462222895619169935317974865296291598100558751976216418469984937110507061979400971905781410388336458908816885758419125375047408388601985300884500733923194700051030733653434466714943605845143519933901592158295809020513235827728686129856549511535000228593790299010401739984240789015389649972633253273119008010971111107028536093543116304613269438082468960788836139999390141570158208410234733780007345264440946888072018632119778442194822690635460883177965078378404035306423001560546174260935441728479454887884057082481520089810271912227350884752023760663");
	
	private static BigInteger q=new BigInteger("63762351364972653564641699529205510489263266834182771617563631363277932854227");
	
	private static BigInteger g=new BigInteger("2");
	
//	private static BigInteger p=new BigInteger("29");	
//	private static BigInteger q=new BigInteger("7");	
//	private static BigInteger g=new BigInteger("5");
//	
////	
//	private static BigInteger p=new BigInteger("199");	
//	private static BigInteger q=new BigInteger("11");	
//	private static BigInteger g=new BigInteger("5");
//	
	
	private static BigInteger ID_A=new BigInteger("101010");
	private static BigInteger ID_B=new BigInteger("100100");
	
	public static void main(String[] args) 
	{
		// DSA params for Alice
		HashMap<String, BigInteger> dsa_Param_for_Alice=generateVerification_And_Signing_Keys_for_DSA(); 
	
		
		//Signing Key for Alice
		BigInteger sk_A=dsa_Param_for_Alice.get("sk");
		
		//Verification Keys for Alice
		// called common function and then assigned particular variable
		HashMap<String, BigInteger> vk_A=new HashMap<String, BigInteger>();
		vk_A.put("y_A", dsa_Param_for_Alice.get("y"));
		vk_A.put("h_A", dsa_Param_for_Alice.get("h"));
		vk_A.put("p_A", dsa_Param_for_Alice.get("p"));
		vk_A.put("q_A", dsa_Param_for_Alice.get("q"));
		
	    
	
		// DH Params for Alice
	    HashMap<String, BigInteger> publicKey_privateKey_for_Alice=generate_DH_PublicKey_PrivateKey_for_Alice();
	    BigInteger dh_privateKey_for_Alice_x=publicKey_privateKey_for_Alice.get("dh_privateKey_for_Alice_x");
	    BigInteger dh_publicKey_for_Alice_X=publicKey_privateKey_for_Alice.get("dh_publicKey_for_Alice_X");
	    
		// PRINTING MESSAGE
		System.out.println("\n----------------------------------------------------");
		System.out.println("DH private key for Alice x:\t"+dh_privateKey_for_Alice_x);
	
		//Generate session key T for Alice
		BigInteger sessionID_T=getSessionID();		
		
		//STEP 1: Alice sends (T,X) to Bob		
		HashMap<String, BigInteger> alice_T_and_X=new HashMap<String, BigInteger>();
		alice_T_and_X.put("sessionID_T",sessionID_T );
		alice_T_and_X.put("dh_publicKey_for_Alice_X", dh_publicKey_for_Alice_X);
		
		 
		//send params to Bob, parameters T, X (g^x)
		HashMap<String, BigInteger> Bob_Params_ReturnValues_Round1=sendParamsToBob_Round1(alice_T_and_X);
			
	
		//get the params from Bob
		BigInteger sessionID_T_from_Bob=Bob_Params_ReturnValues_Round1.get("sessionID_T");
		BigInteger dh_publicKey_for_Bob_Y=Bob_Params_ReturnValues_Round1.get("dh_publicKey_for_Bob_Y");
		BigInteger ID_B=Bob_Params_ReturnValues_Round1.get("ID_B");
		BigInteger tag_B=Bob_Params_ReturnValues_Round1.get("tag_B");
		//signature from B
		BigInteger R_B=Bob_Params_ReturnValues_Round1.get("R_B");
		BigInteger S_B=Bob_Params_ReturnValues_Round1.get("S_B");
		// verification key from Bob
		BigInteger y_B=Bob_Params_ReturnValues_Round1.get("y_B");		
		BigInteger h_B=Bob_Params_ReturnValues_Round1.get("h_B");		
		BigInteger p_B=Bob_Params_ReturnValues_Round1.get("p_B");
		BigInteger q_B=Bob_Params_ReturnValues_Round1.get("q_B");
		
			 		 
	    //VERRIFY
		// Receive the data from signature verifier	 and send it to the verification
		// need to convert to common params for 
		 HashMap<String,BigInteger> signatures_B=new HashMap<String,BigInteger>();
		 signatures_B.put("r",R_B);
		 signatures_B.put("s",S_B );
		 
		 HashMap<String,BigInteger> verification_keys_B=new HashMap<String,BigInteger>();
		 verification_keys_B.put("y", y_B);
		 verification_keys_B.put("h", h_B);
		 verification_keys_B.put("p", p_B);
		 verification_keys_B.put("q", q_B);
		
	      //Generate Z
			BigInteger Z=dh_publicKey_for_Bob_Y.modPow(dh_privateKey_for_Alice_x, q);			// g^xy
			byte[] Key_K0_K1=getMessageDigest_SHA256_InBytes(Z);
            HashMap<String, BigInteger>splitKeys_K0_K1=splitKeys(Key_K0_K1);
			
			//GET THE INDIVISUL KEYS
			BigInteger K0=splitKeys_K0_K1.get("K0");
			BigInteger K1=splitKeys_K0_K1.get("K1");
		    
			System.out.println("\n----------------------------------------------------");
			System.out.println("Keys K0, K1 derived by Alice:");
		    System.out.println("K0    :"+K0);
		    System.out.println("K1    :"+K1);
		    
		    
		    
		    //create a message for tag verification for Alice
			String tag_message_for_Alice=K1.toString().concat(sessionID_T_from_Bob.toString()).concat(ID_B.toString());
			
			BigInteger tag_message_for_Alice_BigInt=new BigInteger(tag_message_for_Alice);
			// create a tag in Alice and compare with received tag
			 BigInteger tag_B_Prime = getMessageDigest_SHA256(tag_message_for_Alice_BigInt);
	
			 // check if tag_B_Prime== tag_B	
				System.out.println("\n----------------------------------------------------");
			  System.out.println("Tag and signature verification results by Alice:");
			
			 if(tag_B_Prime.compareTo(tag_B)==0)
			 {
				  System.out.println("SUCCESS: Tag B verification is successful");
			 }
			 else
			 {
				  System.out.println("Tag B verification failed");
			 }
			
		    
		    //create a message for signature verification for Alice		 
		   String signature_message_for_Alice=sessionID_T_from_Bob.toString().concat(dh_publicKey_for_Alice_X.toString()).concat(dh_publicKey_for_Bob_Y.toString());
		   BigInteger signature_message_for_Alice_BigInt=new BigInteger(signature_message_for_Alice);
		   
		   HashMap<String, BigInteger> verificationResult_for_Signature=verifySignature(signatures_B,verification_keys_B,signature_message_for_Alice_BigInt);
			BigInteger result_signature_verificaiton=verificationResult_for_Signature.get("result");
			if(result_signature_verificaiton.compareTo(BigInteger.ONE)==0)
			{
				System.out.println("SUCCESS: Signature B verification successful");
			}
			else
			{
				System.out.println("Signature B verifiction failed");
			}
		   
		    //__________________________________________________________________________________
			// Next step can be only performed if tag and signature verification can be successful
			HashMap<String,BigInteger> alice_Tag_Signature_ID_Session_Params=new HashMap<String,BigInteger>();
			if((result_signature_verificaiton.compareTo(BigInteger.ONE)==0) && (tag_B_Prime.compareTo(tag_B)==0) )
			{
				// compute signature of A
				  String message_for_Alice_Siganture_Generation=sessionID_T.toString().concat(dh_publicKey_for_Alice_X.toString()).concat(dh_publicKey_for_Bob_Y.toString());
				  
								   
				   //convert to bigInteger
				   BigInteger signature_Alice_BigInteger = new BigInteger(message_for_Alice_Siganture_Generation);
			
					
				   //get back signature
					HashMap<String,BigInteger> signatures_A=getMessageSignature(dsa_Param_for_Alice, signature_Alice_BigInteger);
					BigInteger R_A=signatures_A.get("R");
					BigInteger S_A=signatures_A.get("S");
			
					System.out.println("\n----------------------------------------------------");					
					System.out.println("Printing Signature of A: Sigma_A (R_A, S_A)");
					System.out.println("R_A :"+R_A);
					System.out.println("S_A :"+S_A);
			
					
					// compute tag of A
					//CREATE A TAG  K1||T||IDB
					 String message_for_tag_A=K1.toString().concat(sessionID_T.toString()).concat(ID_A.toString());
					// System.out.println("message_for_tag_a :"+message_for_tag_A);
					
					 BigInteger message_for_tag_A_BigInt=new BigInteger(message_for_tag_A);
					 //create a tag for A
					 BigInteger tag_A = getMessageDigest_SHA256(message_for_tag_A_BigInt);
					
					 System.out.println("\n----------------------------------------------------");
					 System.out.println("Printing tag_A :"+tag_A);
					 
									 
					 alice_Tag_Signature_ID_Session_Params.put("sessionID_T", sessionID_T);
					 alice_Tag_Signature_ID_Session_Params.put("ID_A", ID_A);
					 alice_Tag_Signature_ID_Session_Params.put("tag_A", tag_A);
					 alice_Tag_Signature_ID_Session_Params.put("R_A", R_A);
					 alice_Tag_Signature_ID_Session_Params.put("S_A", S_A);
					 
					 alice_Tag_Signature_ID_Session_Params.put("sessionID_T_Round1", Bob_Params_ReturnValues_Round1.get("sessionID_T_Round1"));
					 alice_Tag_Signature_ID_Session_Params.put("key_K1_Round1",Bob_Params_ReturnValues_Round1.get("key_K1_Round1"));
					 // PUBLIC KEYS OF A AND B
					 
					 alice_Tag_Signature_ID_Session_Params.put("dh_publicKey_for_Alice_X",dh_publicKey_for_Alice_X);
					 alice_Tag_Signature_ID_Session_Params.put("dh_publicKey_for_Bob_Y",dh_publicKey_for_Bob_Y);
					 //verification keys of A					 
					 alice_Tag_Signature_ID_Session_Params.put("y_A",vk_A.get("y_A"));
					 alice_Tag_Signature_ID_Session_Params.put("h_A",vk_A.get("h_A"));				
					 alice_Tag_Signature_ID_Session_Params.put("p_A",vk_A.get("p_A"));
					 alice_Tag_Signature_ID_Session_Params.put("q_A",vk_A.get("q_A"));
			
					 sendParamsToBob_Round2(alice_Tag_Signature_ID_Session_Params);
				
			}
			else
			{
				System.out.println("Cannot procceed as Tag and Signaure verification failed at the Alice Side");
			}
			
		
		 
		
	}//	public static void main(String[] args) 
	
	
	
	
	 // Generate Random Number for DH
	  private static BigInteger getSecretRandomNumber_for_DH()
	{
		BigInteger randomNumber=BigInteger.ZERO;
		try
		{
			 BigInteger randomNumberLowerLimit=BigInteger.ONE;
			 BigInteger randomNumberUpperLimit=q.subtract(BigInteger.ONE);
			
		  do 
		  {
			  SecureRandom secureRandomNumber = new SecureRandom();	
			  randomNumber = new BigInteger(q.bitLength(), secureRandomNumber);
			  
		  }while((randomNumber.compareTo(randomNumberLowerLimit)==-1) || (randomNumber.compareTo(randomNumberUpperLimit)==1));
		  
		}
		catch(Exception ex)
		{
			System.out.println("getSecretRandomNumber_for_DH: Exception occurred while getting randomNumber: "+ex);
		}
		return randomNumber;
	}
	
		
	   //This function will secret number for DSA
		private static BigInteger getSecretRandomNumber_for_DSA()
		{
			BigInteger randomNumber=BigInteger.ZERO;
			try
			{
				 BigInteger randomNumberLowerLimit=BigInteger.TWO;
				 BigInteger randomNumberUpperLimit=q.subtract(BigInteger.ONE);			
				  do 
				  {
					  SecureRandom secureRandomNumber = new SecureRandom();	
					  randomNumber = new BigInteger(q.bitLength(), secureRandomNumber);
					  
				  }while( (randomNumber.compareTo(randomNumberLowerLimit)==-1) || (randomNumber.compareTo(randomNumberUpperLimit)==1) );
			  
			}
			catch(Exception ex)
			{
				System.out.println("Exception occurred while getting randomNumber for DSA: "+ex);
			}
			return randomNumber;
		}
			
	
	//This function will give verification keys
	private static HashMap<String, BigInteger> generateVerification_And_Signing_Keys_for_DSA()
	{
		 HashMap<String, BigInteger> dsa_params=new HashMap<String, BigInteger> ();
		try
		{
		  BigInteger h= BigInteger.ZERO;
		  BigInteger power=(p.subtract(BigInteger.ONE)).divide(q);
		  
		     h =g.modPow(power, p);
		     if(h.compareTo(BigInteger.ONE)==0)
		     {
		    	 System.out.println("h is 1, terminating the program.");
		    	 System.exit(0);
		     }
		     else
		     {	    	  
				  //Generate sk
				 BigInteger sk=getSecretRandomNumber_for_DSA();	
				 // Compute y 
				 BigInteger y=h.modPow(sk, p);				 
				 dsa_params.put("sk", sk);
				 dsa_params.put("y", y);
				 dsa_params.put("h", h);
				 dsa_params.put("p", p);
				 dsa_params.put("q", q);			
		     }
		}
		catch(Exception ex)
		{
			System.out.println("Exception occurred while getting verificaiton keys: "+ex);
		}		
	
		return dsa_params;
	}
	
		
	// Generate DH parameters for Alice
	private static HashMap<String, BigInteger>  generate_DH_PublicKey_PrivateKey_for_Alice()
	{
		HashMap<String, BigInteger> dh_publicKey_and_privateKey=new HashMap<String, BigInteger>(); 
		BigInteger g_pow_X=BigInteger.ZERO;	 
		try
		{
			BigInteger dh_privateKey_for_Alice_x=getSecretRandomNumber_for_DH();
		    g_pow_X=g.modPow(dh_privateKey_for_Alice_x, q);	
		    
		    dh_publicKey_and_privateKey.put("dh_publicKey_for_Alice_X", g_pow_X);
		    dh_publicKey_and_privateKey.put("dh_privateKey_for_Alice_x", dh_privateKey_for_Alice_x);
		}
		catch(Exception ex)
		{
			System.out.println("Exception occurred while generating parameters g pow x for Alice : "+ex);
		}
		return dh_publicKey_and_privateKey;
	}
	
			
	// Get session ID
	private static BigInteger getSessionID()
	{
		BigInteger randomNumber=BigInteger.ZERO;
		try
		{
			 BigInteger randomNumberLowerLimit=BigInteger.ONE;
			 BigInteger randomNumberUpperLimit=q.subtract(BigInteger.ONE);
			
		  do 
		  {
			  SecureRandom secureRandomNumber = new SecureRandom();	
			  randomNumber = new BigInteger(q.bitLength(), secureRandomNumber);
			  
		  }while((randomNumber.compareTo(randomNumberLowerLimit)==-1) || (randomNumber.compareTo(randomNumberUpperLimit)==1));
		  
		}
		catch(Exception ex)
		{
			System.out.println("getSessionID: Exception occurred while getting randomNumber: "+ex);
		}
		return randomNumber;
	}
	
		
	// Generate DH parameters for Bob
	private static HashMap<String, BigInteger> sendParamsToBob_Round1(HashMap<String, BigInteger> Param_for_Alice_Round1)
	{
		
		 HashMap<String, BigInteger> Bob_Params_ReturnValues_Round1=new HashMap<String, BigInteger>();
		try
		{
			BigInteger dh_privateKey_for_Bob_y=getSecretRandomNumber_for_DH();
			BigInteger dh_publicKey_for_Bob_Y=g.modPow(dh_privateKey_for_Bob_y, q); // G^y
				
						
			BigInteger dh_publicKey_for_Alice_X=Param_for_Alice_Round1.get("dh_publicKey_for_Alice_X");                   // DH Public Key g^x
			BigInteger sessionID_T=Param_for_Alice_Round1.get("sessionID_T");                                            // Session Key
			
			System.out.println("DH private key for Bob y  :\t"+dh_privateKey_for_Bob_y);
			
			//Generate Z
			BigInteger Z=dh_publicKey_for_Alice_X.modPow(dh_privateKey_for_Bob_y, q);			
			byte[] Key_K0_K1=getMessageDigest_SHA256_InBytes(Z);
			
			//NEED TO SPLIT K into K0 AND K1
			
			HashMap<String, BigInteger>splitKeys_K0_K1=splitKeys(Key_K0_K1);
			
			//GET THE INDIVISUL KEYS
			BigInteger K0=splitKeys_K0_K1.get("K0");
			BigInteger K1=splitKeys_K0_K1.get("K1");
			
			// COMPUTE SIGNAURE OF BOB		
			// DSA params for Bob
			HashMap<String, BigInteger> dsa_Param_for_Bob=generateVerification_And_Signing_Keys_for_DSA(); 
			
			//Signing Key for Bob
			BigInteger sk_B=dsa_Param_for_Bob.get("sk");
			
			//Verification Keys for Bob
			HashMap<String, BigInteger> vk_B=new HashMap<String, BigInteger>();
			vk_B.put("y_B", dsa_Param_for_Bob.get("y"));
			vk_B.put("h_B", dsa_Param_for_Bob.get("h"));
			vk_B.put("p_B", dsa_Param_for_Bob.get("p"));
			vk_B.put("q_B", dsa_Param_for_Bob.get("q"));						
			
			 System.out.println("\n----------------------------------------------------");
			System.out.println("Keys K0, K1 derived by Bob");
			System.out.println("K0    :"+K0);
			System.out.println("K1    :"+K1);
		 
		    
		  String message_for_Bob_Siganture_Generation=sessionID_T.toString().concat(dh_publicKey_for_Alice_X.toString()).concat(dh_publicKey_for_Bob_Y.toString());
		 
		   
		   //convert to bigInteger
		   BigInteger signature_Bob_BigInteger = new BigInteger(message_for_Bob_Siganture_Generation);

			
		   //get back signature
			HashMap<String,BigInteger> signatures_B=getMessageSignature(dsa_Param_for_Bob, signature_Bob_BigInteger);
			BigInteger R_B=signatures_B.get("R");
			BigInteger S_B=signatures_B.get("S");
	       
			 System.out.println("\n----------------------------------------------------");
			System.out.println("Printing Signature of B Sigma_B(R_B,S_B)");
			System.out.println("R_B :"+R_B);
			System.out.println("S_B :"+S_B);
			  
			  //CREATE A TAG  K1||T||IDB
			 String message_for_tag_B=K1.toString().concat(sessionID_T.toString()).concat(ID_B.toString());
			// System.out.println("message_for_tag_B :"+message_for_tag_B);
			
			 BigInteger message_for_tag_B_BigInt=new BigInteger(message_for_tag_B);
			 //create a tag for B
			 BigInteger tag_B = getMessageDigest_SHA256(message_for_tag_B_BigInt);
		
			 // SEND PARAMS FROM BOB TO ALICE FOR ROUND 2
			 System.out.println("\n----------------------------------------------------");
			 System.out.println("\nPrinting Tag B:\t"+tag_B);
			
				  
			 
			 Bob_Params_ReturnValues_Round1.put("sessionID_T",sessionID_T);
			 Bob_Params_ReturnValues_Round1.put("dh_publicKey_for_Bob_Y", dh_publicKey_for_Bob_Y);
			 Bob_Params_ReturnValues_Round1.put("ID_B", ID_B);
			 Bob_Params_ReturnValues_Round1.put("tag_B",tag_B);
			 Bob_Params_ReturnValues_Round1.put("R_B", R_B);
			 Bob_Params_ReturnValues_Round1.put("S_B", S_B);
			 Bob_Params_ReturnValues_Round1.put("y_B", vk_B.get("y_B"));
			 Bob_Params_ReturnValues_Round1.put("h_B", vk_B.get("h_B"));
			 Bob_Params_ReturnValues_Round1.put("p_B", vk_B.get("p_B"));
			 Bob_Params_ReturnValues_Round1.put("q_B", vk_B.get("q_B"));
			 // below required as I have not implemented persistant values at B's side 
			 // This will be required later
	
			 Bob_Params_ReturnValues_Round1.put("sessionID_T_Round1",sessionID_T);
			 Bob_Params_ReturnValues_Round1.put("key_K1_Round1",K1);		
			 
			 
		}
		catch(Exception ex)
		{
			System.out.println("Exception occurred while generating parameters form Bob : "+ex);
		}
		return Bob_Params_ReturnValues_Round1;
	}
	
		
	
	
	private static void sendParamsToBob_Round2(HashMap<String, BigInteger> Alice_Params_ReturnValues_Round2)
	{
		try
		{		
						
			BigInteger sessionID_T_Round2=Alice_Params_ReturnValues_Round2.get("sessionID_T");		
			BigInteger ID_A=Alice_Params_ReturnValues_Round2.get("ID_A");		
			BigInteger tag_A=Alice_Params_ReturnValues_Round2.get("tag_A");
			BigInteger R_A=Alice_Params_ReturnValues_Round2.get("R_A");
			BigInteger S_A=Alice_Params_ReturnValues_Round2.get("S_A");
		
			BigInteger sessionID_T_Round1=Alice_Params_ReturnValues_Round2.get("sessionID_T_Round1");
			BigInteger key_K1_Round1=Alice_Params_ReturnValues_Round2.get("key_K1_Round1");
			
			BigInteger dh_publicKey_for_Alice_X=Alice_Params_ReturnValues_Round2.get("dh_publicKey_for_Alice_X");
			BigInteger dh_publicKey_for_Bob_Y=Alice_Params_ReturnValues_Round2.get("dh_publicKey_for_Bob_Y");
			
			
			BigInteger y_A= Alice_Params_ReturnValues_Round2.get("y_A");
			BigInteger h_A=Alice_Params_ReturnValues_Round2.get("h_A");
			BigInteger p_A=Alice_Params_ReturnValues_Round2.get("p_A");
			BigInteger q_A=Alice_Params_ReturnValues_Round2.get("q_A");
			
			
			// COMPUTE TAG PRIME PRIME
			 String tag_prime_prime_message=key_K1_Round1.toString().concat(sessionID_T_Round1.toString()).concat(ID_A.toString());
		
			 //Convert to BigInt
			 BigInteger tag_prime_prime_message_BigInt=new BigInteger(tag_prime_prime_message);
			 BigInteger tag_A_Computed_At_Bob = getMessageDigest_SHA256(tag_prime_prime_message_BigInt);
			 
			 System.out.println("\n----------------------------------------------------");
			 System.out.println("Tag and signature verification results by Bob");
			 
			 if(tag_A_Computed_At_Bob.compareTo(tag_A)==0)
			 {
				  System.out.println("SUCCESS: Tag A verification is successful");
			 }
			 else
			 {
				  System.out.println("Tag A verification is failed");
			 }
			 
			 //signature Verification
			 String signature_verificaiton_message=sessionID_T_Round2.toString().concat(dh_publicKey_for_Alice_X.toString()).concat(dh_publicKey_for_Bob_Y.toString());
		
			 BigInteger signature_verificaiton_message_BigInt=new BigInteger(signature_verificaiton_message);
			 
			 
			 HashMap<String,BigInteger> signature_A=new  HashMap<String,BigInteger>();
			 signature_A.put("r",R_A );
			 signature_A.put("s",S_A );
			 
			 HashMap<String,BigInteger> verification_keys_A=new  HashMap<String,BigInteger>();
			 verification_keys_A.put("y", y_A);
			 verification_keys_A.put("h", h_A);
			 verification_keys_A.put("p", p_A);
			 verification_keys_A.put("q", q_A);
			 
			 HashMap<String,BigInteger> verification_result_A=verifySignature(signature_A,verification_keys_A,signature_verificaiton_message_BigInt);
			 BigInteger result_signature_verificaiton=verification_result_A.get("result");
				if(result_signature_verificaiton.compareTo(BigInteger.ONE)==0)
				{
					System.out.println("SUCCESS: Signature of A verified is successful");
				}
				else
				{
					System.out.println("Signature of A verificaiton is failed");
				}
			   
			 
			 
		}
		catch(Exception ex)
		{
			System.out.println("sendParamsToBob_Round2: Exception in round 2 at Bob: "+ex);
		}		
		
	}
	
   //GET MESSAGE DIGEST
	private static byte[]  getMessageDigest_SHA256_InBytes(BigInteger message)
	{
		
		 byte[] decoded_Hash =new byte[256];
		try
		{
			 MessageDigest digest = MessageDigest.getInstance("SHA-256");
			 byte[] encodedhHash = digest.digest(message.toString().getBytes(StandardCharsets.UTF_8));
			 
			 
			 String encoded_hash = Base64.getEncoder().encodeToString(encodedhHash);
			 decoded_Hash= Base64.getDecoder().decode(encoded_hash);	

		}
		catch(Exception ex)
		{
			System.out.println("Exception occurred while getting Message Digest: "+ex);
		}
		return decoded_Hash;
	}

	
	// THIS WILL SPLIT THE KEYS
	private static HashMap<String, BigInteger> splitKeys(byte[] Key_K0_K1)
	{
		HashMap<String, BigInteger> key_store=new HashMap<String, BigInteger>();
		
		
		String K0K1_Hex = String.format("%032x", new BigInteger(1, Key_K0_K1)); 
       // BigInteger K0K1_BigInteger = new BigInteger(K0K1_Hex,  16);
   
        
		try
		{
			byte[] Key_K0=new byte[16];
			byte[] Key_K1=new byte[16];
			for(int i=0,j=0,k=0;i<32;i++)
			{
				if((i>=0) &&(i<16))
				{
					Key_K0[j]=Key_K0_K1[i];
					j++;
					
				}
				else if((i>=16) && (i<32))
				{
				
					Key_K1[k]=Key_K0_K1[i];
					k++;
					 
				}
				
			}
			
			// SIGN MANITURE REPRESENTATION OF BIG INTEGER
	          String K0_Hex = String.format("%032x", new BigInteger(1, Key_K0));
	    
	          BigInteger K0_BigInteger = new BigInteger(K0_Hex,  16);
	  	          
	          String K1_Hex = String.format("%032x", new BigInteger(1, Key_K1));	
	    
	          BigInteger K1_BigInteger = new BigInteger(K1_Hex,  16);
	      
	          
			key_store.put("K0", K0_BigInteger);		
			key_store.put("K1", K1_BigInteger);
		 
			
		}
		catch(Exception ex)
		{
			System.out.println("Exception occurred while splitting the key K into K0 and K1: "+ex);
		}
		return key_store;
	}

	
	
	
    //This function will give signing key
	private static  HashMap<String, BigInteger> getMessageSignature(HashMap<String, BigInteger> verification_and_signing_Keys, BigInteger message)
	{
		HashMap<String, BigInteger> messageSignature=new HashMap<String, BigInteger>();
		 BigInteger k=BigInteger.ZERO;
		 BigInteger r=BigInteger.ZERO;
		 BigInteger k_inverse=BigInteger.ZERO;
		 BigInteger s=BigInteger.ZERO;

		try
		{
			//get the SHA256(message)
			 BigInteger m_SHA256 = getMessageDigest_SHA256(message);
			 BigInteger m_SHA256_modQ =m_SHA256.mod(q);
			 
			 //Get the verification Key		
			 BigInteger x=verification_and_signing_Keys.get("sk");
			 BigInteger h=verification_and_signing_Keys.get("h");						
			 BigInteger y=verification_and_signing_Keys.get("y");
			 
		    do 
		    {
			     //Get the Random Number
			      k=getSecretRandomNumber_K();
			      
				     r=(h.modPow(k,p)).mod(q);
				     k_inverse=k.modInverse(q);
			
				     BigInteger xr=x.multiply(r);
				     BigInteger xr_modQ=xr.mod(q);
				  
			  	     BigInteger sha256_addition_xr=m_SHA256_modQ.add(xr_modQ );	
			  	     s=(k_inverse.multiply(sha256_addition_xr)).mod(q);	


		  	  }while(s.compareTo(BigInteger.ZERO)==0);    
		    
		    messageSignature.put("R", r);
		    messageSignature.put("S", s);
		     	 
		}
		catch(Exception ex)
		{
			System.out.println("getMessageSignature: Exception occurred while getting randomNumber: "+ex);
		}		
	
		return messageSignature;
	}
	

	// GET MESSAGE DIGEST
	private static BigInteger getMessageDigest_SHA256(BigInteger message)
	{
		
		 BigInteger hash_BigInteger=BigInteger.ZERO;
		try
		{
			 MessageDigest digest = MessageDigest.getInstance("SHA-256");
			 byte[] encodedhHash = digest.digest(message.toString().getBytes(StandardCharsets.UTF_8));
			 					 
			 String encoded_hash = Base64.getEncoder().encodeToString(encodedhHash);
			 byte[] decoded_Hash = Base64.getDecoder().decode(encoded_hash);	
			 
			 
			// SIGN MANITURE REPRESENTATION OF BIG INTEGER
	          String hash256_HEX = String.format("%032x", new BigInteger(1, decoded_Hash));	 
	          	      			 
			  //Converting hex to BigInteger
	          hash_BigInteger = new BigInteger(hash256_HEX,  16);
		}
		catch(Exception ex)
		{
			System.out.println("Exception occurred while getting Message Digest: "+ex);
		}
		return hash_BigInteger;
	}
	
	
	//GET THE RANDOM NUMNER K
	private static BigInteger getSecretRandomNumber_K()
	{
		BigInteger randomNumber=BigInteger.ZERO;
		try
		{
			 BigInteger randomNumberLowerLimit=BigInteger.TWO;
			 BigInteger randomNumberUpperLimit=q.subtract(BigInteger.ONE);
			
		  do 
		  {
			  SecureRandom secureRandomNumber = new SecureRandom();	
			  randomNumber = new BigInteger(q.bitLength(), secureRandomNumber);
			  
		  }while( (randomNumber.compareTo(randomNumberLowerLimit)==-1) || (randomNumber.compareTo(randomNumberUpperLimit)==1) );
		  
		}
		catch(Exception ex)
		{
			System.out.println("getSecretRandomNumber_K: Exception occurred while getting randomNumber: "+ex);
		}
		return randomNumber;
	}
	
	
	
	//VERIFY SIGNATURE
	private static  HashMap<String, BigInteger> verifySignature(HashMap<String,BigInteger> signature,HashMap<String,BigInteger> verification_keys, BigInteger message)
	{
		 HashMap<String, BigInteger>  signatureVerification=new  HashMap<String, BigInteger>();
		try
		{
			
			BigInteger r_signture=signature.get("r");
			BigInteger s_signature=signature.get("s");
			BigInteger h_publicKey=verification_keys.get("h");
			BigInteger y_publicKey=verification_keys.get("y");
				
		    BigInteger messageHash=getMessageDigest_SHA256(message);
			
							
		    BigInteger w=s_signature.modInverse(q);	
		    
			// (A * B) mod C = (A mod C * B mod C) mod C			    
		    // u1 = w × SHA256(m) mod q
		    BigInteger w_modQ=w.mod(q);
		    
		    BigInteger hash_256_modq=messageHash.mod(q);
		    
			// (A * B) mod C = (A mod C * B mod C) mod C	
			BigInteger u1=(w_modQ.multiply(hash_256_modq)).mod(q);
			
			// u2 = r × w mod q
			BigInteger r_signature_modQ=r_signture.mod(q);
			
			BigInteger u2=(r_signature_modQ.multiply(w_modQ)).mod(q);
			
			
			//get public key			
			// (A * B) mod C = (A mod C * B mod C) mod C
			BigInteger multiplier_1=h_publicKey.modPow(u1, p);
			BigInteger multiplier_2=y_publicKey.modPow(u2, p);		
			
			BigInteger result=(multiplier_1.multiply(multiplier_2)).mod(p);
			
			BigInteger v=result.mod(q);
			
			BigInteger signatureVerificationResult=BigInteger.ZERO;
			if(  ( v.toString()!=null) && (r_signture.toString()!=null))
			{
				if(v.compareTo(r_signture)==0)
				{
					signatureVerificationResult=BigInteger.ONE;
				}
				else
				{
					signatureVerificationResult=BigInteger.ZERO;
				}
			}
			else
			{
				System.out.println("result v or r is null");
			}
			
			signatureVerification.put("w", w);
			signatureVerification.put("u1", u1);
			signatureVerification.put("u2", u2);
			signatureVerification.put("v", v);
			signatureVerification.put("result", signatureVerificationResult);
			
			
		}		
	   catch(Exception ex)
		{
			System.out.println("Exception occurred while verifying signature: "+ex);
		}
		return signatureVerification;
	}
	
	
}//CLASSS






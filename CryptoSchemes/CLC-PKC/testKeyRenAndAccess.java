import java.security.NoSuchAlgorithmException;
import it.unisa.dia.gas.jpbc.Element;

public class testKeyRenAndAccess {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        keyRenAndAccess keyRenewalAndKeyAccessAlgos = new keyRenAndAccess();
        // Run setup algorithm.
        keyRenewalAndKeyAccessAlgos.setup();

        // Set Time main bound T_M.
        int T_Minput = 30;
        int T_M = keyRenewalAndKeyAccessAlgos.initTimeFrame(T_Minput);
        System.out.println("Main time bound T_M set: "+ T_M);

        // User ID
        String userID = "justnetorgani@github.com";

        // Set Secret value....sets secret value and outputs Y_i value.
        Element Y_i = keyRenewalAndKeyAccessAlgos.setSecretValue(userID);
        // Get Public key.
        Element[] PubKeyValues = keyRenewalAndKeyAccessAlgos.setPublicKey(userID, T_M, Y_i);
        System.out.println("Public key: "+ PubKeyValues);

        // Time
        int T_D = 15;

        // Run KeyExtract algorithm.
        Element D_i = keyRenewalAndKeyAccessAlgos.partialPrivateKeyExtract(userID, T_M);
        System.out.println("Partial private key: "+ D_i); // Partial private key.

        // Run SetPrivatekey algorithm.
        Element[] secrets = keyRenewalAndKeyAccessAlgos.setPrivateKey(userID, D_i, T_M, T_D);

        // Run Key renewal algorithm: Simulate via loop.
        int nextT_D = 29;
        for(int i=nextT_D; i<=T_M+1; i++){
            Element EphemKey = keyRenewalAndKeyAccessAlgos.keyRenewal(secrets, T_M, i);
            if(EphemKey.isZero()==false){
                System.out.println("Renewed Ephemeral secret key: " + EphemKey);
            }
        }

        // Run Key access algorithm.
        int prevT_D = T_D; 
        Element EphKeyAccessed = keyRenewalAndKeyAccessAlgos.keyAccess(secrets, userID, T_M, prevT_D);
        // Check equality with initial.
        if(secrets[2].isEqual(EphKeyAccessed)){
            System.out.println("Ephemeral key accessed matches previous key.");
            System.out.println("Renewed Ephemeral secret key: " + EphKeyAccessed);
        } else{
            System.out.println("Ephemeral key accessed does not match initial key.");
        }
    }
}

import java.security.NoSuchAlgorithmException;
import it.unisa.dia.gas.jpbc.Element;
// import java.util.*;
public class testKeyRenExtnAcc {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        keyExtnAccess pairingBasedRS = new keyExtnAccess();
        // Run setup algorithm.
        pairingBasedRS.setup();

        // Set Time main bound T_M.
        int T_Minput = 30;
        int T_M = pairingBasedRS.initTimeFrame(T_Minput);
        System.out.println("Main time bound T_M set: "+ T_M);

        // Run KeyExtract algorithm.
        String userID = "justnetorgani@github.com";
        int T_D = 15;
        Element[] userSecrets = pairingBasedRS.keyExtract(userID, T_M, T_D);
        System.out.println("User secrets generated. Main sk: "+ userSecrets[0]); // main Secret key
        System.out.println("User secrets generated. Ephemeral sk: "+ userSecrets[1]); // Ephemeral Secret Key

        // Run Key renewal algorithm: Simulate via loop.
        int nextT_D = 29;
        for(int i=nextT_D; i<=T_M+1; i++){
            Element sampleEphKey = pairingBasedRS.keyRenewal(userSecrets[0], T_M, i);
            if(sampleEphKey.isZero()==false){
                System.out.println("Renewed Ephemeral secret key: " + sampleEphKey);
            }
        }

        // Run Key access algorithm.
        int prevT_D = T_D; 
        Element EphKeyAccessed = pairingBasedRS.keyAccess(userSecrets[0], userID, prevT_D);
        // Check equality with initial.
        if(userSecrets[1].isEqual(EphKeyAccessed)){
            System.out.println("Ephemeral key accessed matches initial key.");
        } else{
            System.out.println("Ephemeral key accessed does not match initial key.");
        }
    }
}

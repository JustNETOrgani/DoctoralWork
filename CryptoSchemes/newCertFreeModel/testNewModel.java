import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import it.unisa.dia.gas.jpbc.Element;

public class testNewModel {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        newModel proposedModel = new newModel();
        // Run setup algorithm.
        proposedModel.setup();
        // Sample User ID.
        String userID = "justnetorgani@github.com";
        // Set user public params.
        Element U_ID_i = proposedModel.userSecretValueSelect(userID);
        System.out.println("============ User Public Parameters ==============");
        System.out.println("userID: "+ userID);
        System.out.println("============== User Public Parameters ===============");

        // Set Time main bound T_M.
        int T_M = 30;

        // Trusted entity sets designated user's key.
        ArrayList<specificUserParams> designatedUserPubParams = proposedModel.setUser(userID, U_ID_i, T_M);

        // Designated user runs key extract.
        int T_D = 10;
        Element[] userSecretKeys = proposedModel.extractUserCredentials(designatedUserPubParams, userID, T_M, T_D);
        if (userSecretKeys[0].isZero() == false){
            System.out.println("============ User Secret Keys ==============");
            System.out.println("Main secret key: "+ userSecretKeys[0]);
            System.out.println("Ephemeral secret key: "+ userSecretKeys[1]);
            System.out.println("============== User Secret Keys  ===============");
        } else {
            System.out.println("Ooops! Execution error.");
        }

        // Test keyRenewal. Run Key renewal algorithm: Simulate via loop.
        for(int nextT_D=28; nextT_D<=T_M; nextT_D++){
            Element EphemKey = proposedModel.keyRenewal(userID, userSecretKeys[0], T_M, nextT_D);
            if(EphemKey.isZero()==false){
                System.out.println("Renewed Ephemeral secret key: " + EphemKey);
            }
        }

        // Run Key access algorithm.
        int prevT_D = T_D; // Here, T_D=10
        Element EphKeyAccessed = proposedModel.keyAccess(userID, userSecretKeys[0], prevT_D);
        // Check equality with initial.
        if(userSecretKeys[1].isEqual(EphKeyAccessed)){
            System.out.println("Ephemeral key accessed matches previous key.");
            System.out.println("Accessed Ephemeral secret key: " + EphKeyAccessed);
        } else{
            System.out.println("Ephemeral key accessed does not match initial key.");
        }
        
    }
}

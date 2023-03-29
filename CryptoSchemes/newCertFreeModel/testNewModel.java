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
        int T_D = 15;
        Element[] userSecretKeys = proposedModel.extractUserCredentials(designatedUserPubParams, userID, T_M, T_D);
        if (userSecretKeys[0].isZero() == false){
            System.out.println("============ User Secret Keys ==============");
            System.out.println("Main secret key: "+ userSecretKeys[0]);
            System.out.println("Ephemeral secret key: "+ userSecretKeys[1]);
            System.out.println("============== User Secret Keys  ===============");
        } else {
            System.out.println("Ooops! Execution error.");
        }
        
    }
}

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import it.unisa.dia.gas.jpbc.Element;

public class testSCFv3 {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        SCFv3 scfV3 = new SCFv3();
        // Run setup algorithm.
        scfV3.setup();
        // Sample User ID.
        String userID = "justnetorgani@github.com";
        // Set user public params.
        Element Y_i = scfV3.setSecretValue(userID);
        System.out.println("============ User Public Parameters ==============");
        System.out.println("userID: "+ userID);
        //System.out.println("Y_i: "+ Y_i);
        System.out.println("============== User Public Parameters ===============");

        // Set Time main bound T_M.
        int T_M = 30;

        // Trusted entity sets designated user's key.
        ArrayList<designatedUserParamSCFv3> designatedUserPubParams = scfV3.partialPrivateKeyExtract(userID, Y_i, T_M);

        // Designated user runs key extract.
        int T_D = 15;
        Element[] userKeys = scfV3.setPrivateKey(designatedUserPubParams, userID, T_M, T_D);
        if (userKeys.length>1){
            System.out.println("============ User Private Keys ==============");
            System.out.println("Extracted Partial private key: "+ userKeys[1]);
            System.out.println("User secret value: "+ userKeys[0]);
            System.out.println("============== User Private Keys  ===============");
        } else {
            System.out.println("Ooops! Execution error.");
        }
        
    }
}

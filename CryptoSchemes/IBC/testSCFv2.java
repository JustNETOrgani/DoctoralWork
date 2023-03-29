import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import it.unisa.dia.gas.jpbc.Element;

public class testSCFv2 {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        SCFv2 scfV2 = new SCFv2();
        // Run setup algorithm.
        scfV2.setup();
        // Sample User ID.
        String userID = "justnetorgani@github.com";
        // Set user public params.
        Element U = scfV2.setUserPubParam(userID);
        System.out.println("============ User Public Parameters ==============");
        System.out.println("userID: "+ userID);
        System.out.println("U: "+ U);
        System.out.println("============== User Public Parameters ===============");

        // Set Time main bound T_M.
        int T_M = 30;

        // Trusted entity sets designated user's key.
        ArrayList<designatedUserParam> designatedUserPubParams = scfV2.setDesigUserKey(userID, U, T_M);

        // Designated user runs key extract.
        int T_D = 15;
        Element[] userKeys = scfV2.userKeyExtract(designatedUserPubParams, userID, T_M, T_D);
        if (userKeys.length>1){
            System.out.println("============ User Private Keys ==============");
            System.out.println("MAIN: "+ userKeys[0]);
            System.out.println("EPHEMERAL: "+ userKeys[1]);
            System.out.println("============== User Private Keys  ===============");
        } else {
            System.out.println("Ooops! Execution error.");
        }
        
    }
}

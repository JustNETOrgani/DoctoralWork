import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class SCFv3 {
    private cryptoParams cryptoParam;        // Public Key Parameters.
    private Element x;                      // Master Secret Key.
    public Element X;                       // Master Public Key.
    private Element x_i;                    // User secret value.

    public void setup(){
        // Setup must be run only once:
        if (cryptoParam != null && x != null) {
            System.out.println("Setup already executed!");
            return;
        }
        // Initialise Pairing and its Parameters:
        cryptoParam = new cryptoParams();
        cryptoParam.pairing = PairingFactory.getPairing("params.properties"); // Get parameters from file.

        // For ease of use. Returns random elements.
        cryptoParam.G1 = cryptoParam.pairing.getG1();
        cryptoParam.Gt = cryptoParam.pairing.getGT();
        cryptoParam.Zr = cryptoParam.pairing.getZr();
        cryptoParam.g  = cryptoParam.G1.newRandomElement(); // This acts as random generator.

        // Set master secret/private key x = random with Zr.
        x = (cryptoParam.Zr.newRandomElement()).getImmutable();

        // Set Master Public Key. X = g^x
        X = ((cryptoParam.g.duplicate()).powZn(x)).getImmutable();

        // Display public values.
        printStatements();
    }

    public Element setSecretValue(String userID) throws NoSuchAlgorithmException{
        x_i = cryptoParam.Zr.newRandomElement();
        Element Y_i = cryptoParam.G1.newElement();
        Y_i = ((cryptoParam.g.duplicate()).powZn(x_i)).getImmutable();
        return Y_i;
    }

    public ArrayList<designatedUserParamSCFv3> partialPrivateKeyExtract(String userID, Element Y_i, int T_M) throws NoSuchAlgorithmException{
        // Initialise elements:
        designatedUserParamSCFv3 userSpecificParams = new designatedUserParamSCFv3();
        Element Q_ID_i = cryptoParam.G1.newRandomElement();
        String prepHash_1 = userID + T_M;
        hashFunc(Q_ID_i, prepHash_1);
        Element D_i = Q_ID_i.powZn(x);
        System.out.println("============ User Private data ==============");
        System.out.println("Partial private key from KGC: "+D_i);
        System.out.println("============ User Private data ==============");
        userSpecificParams.s = cryptoParam.Zr.newElement();
        String prepHash_3 = userID + T_M + D_i;
        hashFunc(userSpecificParams.s, prepHash_3);
        userSpecificParams.Y_ID_i = cryptoParam.G1.newElement();
        userSpecificParams.Y_ID_i = (Y_i.powZn(x.mulZn(userSpecificParams.s))).mul(D_i);
        userSpecificParams.Y_i = Y_i;
        // Prepare arrayList for return statement.
        ArrayList<designatedUserParamSCFv3> designatedUserPubParams = new ArrayList<>();
        designatedUserPubParams.add(userSpecificParams);
        printDesigUserParams(designatedUserPubParams);
        return designatedUserPubParams;
    }

    public Element[] setPrivateKey(ArrayList<designatedUserParamSCFv3> desigUserParam, String userID, int T_M, int T_D) throws NoSuchAlgorithmException{
        // Logic => D_i = Y_ID_i * X^{-x_i.s}
        Element D_i = (X.powZn(x_i.negate().mulZn(desigUserParam.get(0).s))).mul(desigUserParam.get(0).Y_ID_i);
        // Check ownership.
        Element sComputed = cryptoParam.Zr.newElement();
        String prepHash_3 = userID + T_M + D_i;
        hashFunc(sComputed, prepHash_3);
        Element[] returnedVals = { x_i, D_i};
        if (sComputed.isEqual(desigUserParam.get(0).s)){
            System.out.println("Key ownership check passed.");
            //Check key correctness.
            Element Q_ID_i = cryptoParam.G1.newRandomElement();
            String prepHash_1 = userID + T_M;
            hashFunc(Q_ID_i, prepHash_1);
            Element outLeft = cryptoParam.pairing.pairing(D_i, cryptoParam.g.duplicate());
            Element outRight = cryptoParam.pairing.pairing(Q_ID_i, X);
            if (outLeft.isEqual(outRight)){
                System.out.println("Key correctness check passed.");
                return returnedVals;
            } else {
                System.out.println("Key correctness check failed.");
                returnedVals[0].setToZero();
                returnedVals[1].setToZero();
                return returnedVals;
            }
        } else {
            System.out.println("Key ownership check failed. Execution aborted");
            returnedVals[0].setToZero();
            returnedVals[1].setToZero();
            return returnedVals;
        }
    }

    // ======================= Utility functions =======================
    public void printStatements() {
        System.out.println("============ Public Key Parameters ==============");
        System.out.println("Generator (g): " +cryptoParam.g);
        System.out.println("============== PKG Parameters ===============");
        System.out.println("PRIVATE KEY OF KGC x : "+x);
        System.out.println("PUBLIC KEY OF KGC X : "+X);
        System.out.println("=================================================\n");
    }

    public void printDesigUserParams(ArrayList<designatedUserParamSCFv3> dUparams) {
        System.out.println("============ Specific user Public Parameters ==============");
        System.out.println("Y_i: "+ dUparams.get(0).Y_i);
        System.out.println("Y_ID_i: "+ dUparams.get(0).Y_ID_i);
        System.out.println("s: "+ dUparams.get(0).s);
        System.out.println("=================================================\n");
    }

    // Hashing algorithms begin. Specific usage will depend on output required for each method.
    // e.g In case of hash to group => Element hashed_message = cryptoParam.G1.newElement(); hashFunc(hashed_message, message);
    private static void hashFunc(Element h, String s) throws NoSuchAlgorithmException{
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(s.getBytes());
        h.setFromHash(digest, 0, digest.length);
    }
}

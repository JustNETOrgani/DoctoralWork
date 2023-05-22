import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class KeyIssuance {
    private cryptoParams cryptoParam;        // Public Key Parameters.
    private KGCkeyStore KGCkeys;        // Public Key Parameters.
    private Element x_i;                    // User secret value.
    
    userData protocolUserData = new userData();
    designatedUserParamSCFv3 userSpecificParams = new designatedUserParamSCFv3();

    public void CryptoSetup(){
        // Setup must be run only once:
        if (cryptoParam != null) {
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

        // Initialize KGC key store.
        KGCkeys = new KGCkeyStore();

        // Set master secret/private key x = random with Zr.
        KGCkeys.x = (cryptoParam.Zr.newRandomElement()).getImmutable();

        // Set Master Public Key. X = g^x
        KGCkeys.X = ((cryptoParam.g.duplicate()).powZn(KGCkeys.x)).getImmutable();
        System.out.println("Key issuance setup executed!");
    }

    public Element[] setSecretValue(String userID) throws NoSuchAlgorithmException{
        CryptoSetup();
        x_i = cryptoParam.Zr.newRandomElement();
        protocolUserData.Y_i = ((cryptoParam.g.duplicate()).powZn(x_i)).getImmutable();
        // Hash ID to group element.
        Element hID = cryptoParam.Zr.newRandomElement();
        hashFunc(hID, userID);
        protocolUserData.ID = userID;
        Element[] uData = {hID, protocolUserData.Y_i};
        return uData;
    }

    public Element[] partialPrivateKeyExtract(String userID) throws NoSuchAlgorithmException{
        CryptoSetup();
        Element Q_ID_i = cryptoParam.G1.newRandomElement();
        String prepHash_1 = userID + cryptoParam.T_M;
        hashFunc(Q_ID_i, prepHash_1);
        Element D_i = Q_ID_i.powZn(KGCkeys.x);
        userSpecificParams.s = cryptoParam.Zr.newElement();
        String prepHash_3 = userID + cryptoParam.T_M + D_i;
        hashFunc(userSpecificParams.s, prepHash_3);
        userSpecificParams.Y_ID_i = cryptoParam.G1.newElement();
        userSpecificParams.Y_i = protocolUserData.Y_i;
        userSpecificParams.Y_ID_i = (userSpecificParams.Y_i.powZn(KGCkeys.x.mulZn(userSpecificParams.s))).mul(D_i);
        Element[] data = {userSpecificParams.s,userSpecificParams.Y_ID_i};
        return data;
    }

    public Element[] keyExtraction(String userID) throws NoSuchAlgorithmException{
        // Logic => D_i = Y_ID_i * X^{-x_i.s}
        System.out.println("============ Embedded key retrieved from blockchain ==============");
        System.out.println(userSpecificParams.Y_ID_i);
        Element D_i = (KGCkeys.X.powZn(x_i.negate().mulZn(userSpecificParams.s))).mul(userSpecificParams.Y_ID_i);
        // Check ownership.
        Element sComputed = cryptoParam.Zr.newElement();
        String prepHash_3 = userID + cryptoParam.T_M + D_i;
        hashFunc(sComputed, prepHash_3);
        Element[] returnedVals = { x_i, D_i};
        if (sComputed.isEqual(userSpecificParams.s)){
            //System.out.println("Key ownership check passed.");
            //Check key correctness.
            Element Q_ID_i = cryptoParam.G1.newRandomElement();
            String prepHash_1 = userID + cryptoParam.T_M;
            hashFunc(Q_ID_i, prepHash_1);
            Element outLeft = cryptoParam.pairing.pairing(D_i, cryptoParam.g.duplicate());
            Element outRight = cryptoParam.pairing.pairing(Q_ID_i, KGCkeys.X);
            if (outLeft.isEqual(outRight)){
                System.out.println("*****Status of checking mechanisms: Passed.****");
                return returnedVals;
            } else {
                //System.out.println("Key correctness check failed.");
                returnedVals[0].setToZero();
                returnedVals[1].setToZero();
                return returnedVals;
            }
        } else {
            //System.out.println("Key ownership check failed. Execution aborted");
            returnedVals[0].setToZero();
            returnedVals[1].setToZero();
            return returnedVals;
        }
    }

    // Hashing algorithms begin. Specific usage will depend on output required for each method.
    // e.g In case of hash to group => Element hashed_message = cryptoParam.G1.newElement(); hashFunc(hashed_message, message);
    private static void hashFunc(Element h, String s) throws NoSuchAlgorithmException{
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(s.getBytes());
        h.setFromHash(digest, 0, digest.length);
    }
}

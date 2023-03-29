import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class keyRenAndAccess {
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

    public int initTimeFrame(int T_M){// To be improved.
        // Require that Setup must have been run:
        if (cryptoParam == null && x.isZero()==true) {
            System.out.println("First execute Setup!");
            return 0;
        }
        return T_M;
    }

    public Element setSecretValue(String userID) throws NoSuchAlgorithmException{
        x_i = cryptoParam.Zr.newRandomElement();
        Element Y_i = cryptoParam.G1.newElement();
        Y_i = ((cryptoParam.g.duplicate()).powZn(x_i)).getImmutable();
        return Y_i;
    }

    public Element partialPrivateKeyExtract(String userID, int T_M) throws NoSuchAlgorithmException{
        Element Q_ID_i = cryptoParam.G1.newRandomElement();
        String prepHash_1 = userID + T_M;
        hashFunc(Q_ID_i, prepHash_1);
        Element D_i = Q_ID_i.duplicate().mulZn(x);
        System.out.println("============ User Private data ==============");
        System.out.println("Partial private key from KGC: "+D_i);
        System.out.println("User Q_ID_i: "+ Q_ID_i);
        System.out.println("============ User Private data ==============");
        return D_i;
    }

    public Element[] setPrivateKey(String userID, Element D_i, int T_M, int T_D) throws NoSuchAlgorithmException{
        Element ephemKey = cryptoParam.G1.newElement();
        Element[] secrets = { x_i.duplicate(), D_i.duplicate(), ephemKey};
        Element outLeft = cryptoParam.pairing.pairing(D_i.duplicate(), cryptoParam.g.duplicate());
        Element Q_ID_i = cryptoParam.G1.newElement();
        String prepHash_1 = userID + T_M;
        hashFunc(Q_ID_i, prepHash_1);
        Element outRight = cryptoParam.pairing.pairing(Q_ID_i.duplicate(), X);
        if (outLeft.isEqual(outRight)){
            System.out.println("Partial private key is correct.");
            // Compute ephem. key.
            Element t_p = cryptoParam.Zr.newElement();
            String T_D_converted = Integer.toString(T_D);
            hashFunc(t_p, T_D_converted);
            ephemKey = (D_i.mulZn(x_i)).mulZn(t_p);
            secrets[2] = ephemKey;
            return secrets;
        } else {
            System.out.println("Key correctness check failed.");
            secrets[0].setToZero();
            secrets[1].setToZero();
            secrets[2].setToZero();
            return secrets;
        }
    }

    public Element[] setPublicKey(String userID, int T_M, Element Y_i) throws NoSuchAlgorithmException{
        Element Q_ID_i = cryptoParam.G1.newElement();
        String prepHash_1 = userID + T_M;
        hashFunc(Q_ID_i, prepHash_1);
        Element[] pubKeyVals = {Y_i, Q_ID_i};
        return pubKeyVals;
    }

    public Element keyRenewal(Element[] secrets, int T_M, int nextT_D) throws NoSuchAlgorithmException{
        Element ephemKey = cryptoParam.G1.newRandomElement();
        if (nextT_D <= T_M){
            // Compute ephem. key.
            Element t_p = cryptoParam.Zr.newElement();
            String T_D_converted = Integer.toString(nextT_D);
            hashFunc(t_p, T_D_converted);
            ephemKey = (secrets[1].duplicate().mulZn(secrets[0].duplicate())).mulZn(t_p.duplicate());
            return ephemKey;
        }else{
            ephemKey.setToZero(); // Added for loop purposes.
            System.out.println("Sorry! Ephemeral secret key cannot be renewed: Time bound exceeded.");
            return ephemKey;
        }
    }

    public Element keyAccess(Element[] secrets, String userID, int T_M, int prevT_D) throws NoSuchAlgorithmException{
        Element ephemKey = cryptoParam.G1.newRandomElement();
        Element outLeft = cryptoParam.pairing.pairing(secrets[1].duplicate(), cryptoParam.g.duplicate());
        Element Q_ID_i = cryptoParam.G1.newElement();
        String prepHash_1 = userID + T_M;
        hashFunc(Q_ID_i, prepHash_1);
        Element outRight = cryptoParam.pairing.pairing(Q_ID_i.duplicate(), X);
        // Check validity of current partial private key.
        if (outLeft.isEqual(outRight)){
            System.out.println("Current Partial private key is correct.");
            // Compute past ephem. key.
            // Get past T_M from prevT_D
            int prev_T_M = prevT_D*2; // Highly abstracted.
            Element prev_Q_ID_i = cryptoParam.G1.newElement();
            String prev_prepHash_1 = userID + prev_T_M;
            hashFunc(prev_Q_ID_i, prev_prepHash_1);
            Element prev_D_i = prev_Q_ID_i.duplicate().mulZn(x);
            System.out.println("Previous Partial private key from KGC: "+ prev_D_i);
            System.out.println("User previous Q_ID_i: "+ prev_Q_ID_i);
            // User checks received prev_D_i.
            Element outLeftPaired = cryptoParam.pairing.pairing(prev_D_i.duplicate(), cryptoParam.g.duplicate());
            Element outRightPaired = cryptoParam.pairing.pairing(prev_Q_ID_i.duplicate(), X);
            if (outLeftPaired.isEqual(outRightPaired)){
                System.out.println("Received Partial private key is correct.");
                // Compute ephem. key.
                Element t_p = cryptoParam.Zr.newElement();
                String T_D_converted = Integer.toString(prevT_D);
                hashFunc(t_p, T_D_converted);
                ephemKey = (prev_D_i.duplicate().mulZn(secrets[0].duplicate())).mulZn(t_p);
                return ephemKey;
            } else {
                System.out.println("Received Partial Key correctness check failed.");
                return ephemKey.setToZero();
            }
        } else {
            System.out.println("Current Partial Key correctness check failed.");
            return ephemKey.setToZero();
        }
    }

    // ======================= Helper Functions Below =======================
    public void printStatements() {
        System.out.println("============ Public Key Parameters ==============");
        System.out.println("G1: "+cryptoParam.G1);
        System.out.println("Gt: "+cryptoParam.Gt);
        System.out.println("Zr: "+cryptoParam.Zr);
        System.out.println("g: " +cryptoParam.g);
        System.out.println("============== KGC Parameters ===============");
        System.out.println("PRIVATE KEY OF KGC x : "+x);
        System.out.println("PUBLIC KEY OF KGC X : "+X);
        System.out.println("=================================================\n");
    }

    // Hashing algorithms begin. Specific usage will depend on output required for each method.
    // e.g In case of hash to group => Element hashed_message = cryptoParam.G1.newElement(); hashFunc(hashed_message, message);
    private static void hashFunc(Element h, String s) throws NoSuchAlgorithmException{
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(s.getBytes());
        h.setFromHash(digest, 0, digest.length);
    }
    // Hashing algorithms end.
}

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class newModel {
    private cryptoParams cryptoParam;        // Public Key Parameters.
    private Element x;                      // Master Secret Key.
    public Element X;                       // Master Public Key.
    private Element u;                    // User secret value.

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

        // Set Master Public Key. X = xG
        X = ((cryptoParam.g.duplicate()).mulZn(x)).getImmutable();

        // Display public values.
        printStatements();
    }

    public Element userSecretValueSelect(String userID) throws NoSuchAlgorithmException{
        u = cryptoParam.Zr.newRandomElement();
        Element U_ID_i = cryptoParam.G1.newElement();
        U_ID_i = ((cryptoParam.g.duplicate()).mulZn(u)).getImmutable();
        return U_ID_i;
    }

    public ArrayList<specificUserParams> setUser(String userID, Element U_ID_i, int T_M) throws NoSuchAlgorithmException{
        // Initialise elements:
        specificUserParams userSpecificParams = new specificUserParams();
        Element Q_ID_i = cryptoParam.G1.newElement();
        String prepHash_1 = userID + T_M;
        hashFunc(Q_ID_i, prepHash_1);
        Element K_ID_i = (Q_ID_i.mulZn(x)).getImmutable();
        userSpecificParams.s = (cryptoParam.Zr.newRandomElement()).getImmutable();
        userSpecificParams.V_ID_i = ((U_ID_i.powZn(x.mulZn(userSpecificParams.s.duplicate()))).mul(K_ID_i)).getImmutable();
        Element f = cryptoParam.Zr.newRandomElement();
        Element F = ((cryptoParam.g.duplicate()).mulZn(f)).getImmutable();
        System.out.println("F value from EBKG : "+F);
        // Compute challenge value.
        userSpecificParams.e = cryptoParam.Zr.newElement();
        String prepHash_2 = Integer.toString(F.duplicate().getLengthInBytes()) + userSpecificParams.V_ID_i.duplicate() + userSpecificParams.s.duplicate();
        hashFunc(userSpecificParams.e, prepHash_2);
        // Compute response value.
        userSpecificParams.v = (f.sub(userSpecificParams.e.duplicate().mulZn(x))).getImmutable();
        System.out.println("============ User Private data ==============");
        System.out.println("Base key from EBKG: "+K_ID_i);
        System.out.println("============ User Private data ==============");
        // Prepare arrayList for return statement.
        ArrayList<specificUserParams> designatedUserPubParams = new ArrayList<>();
        designatedUserPubParams.add(userSpecificParams);
        printDesigUserParams(designatedUserPubParams);
        return designatedUserPubParams;
    }

    public Element[] extractUserCredentials(ArrayList<specificUserParams> desigUserParam, String userID, int T_M, int T_D) throws NoSuchAlgorithmException{
        // Compute F value.
        Element computed_F = (cryptoParam.g.duplicate().mulZn(desigUserParam.get(0).v.duplicate())).add(X.mulZn(desigUserParam.get(0).e.duplicate()));
        Element eComputed = cryptoParam.Zr.newElement();
        String prepHash_2 = Integer.toString(computed_F.duplicate().getLengthInBytes()) + desigUserParam.get(0).V_ID_i.duplicate() + desigUserParam.get(0).s.duplicate();
        hashFunc(eComputed, prepHash_2);
        // Prepare secret keys.
        Element mainSk = cryptoParam.G1.newElement();
        Element ephemSk = cryptoParam.G1.newElement();
        Element[] secretKeys = {mainSk, ephemSk};
        if (eComputed.isEqual(desigUserParam.get(0).e)){
            System.out.println("Passed data assurance from EBKG and data integrity");
            System.out.println("Extracting base key...");
            Element K_ID_i = (X.powZn(u.negate().mulZn(desigUserParam.get(0).s))).mul(desigUserParam.get(0).V_ID_i);
            // Check ownership and validity simultaneously.
            System.out.println("Now checking ownership and correctness.");
            Element Q_ID_i = cryptoParam.G1.newRandomElement();
            String prepHash_1 = userID + T_M;
            hashFunc(Q_ID_i, prepHash_1);
            Element outLeft = cryptoParam.pairing.pairing(K_ID_i, cryptoParam.g.duplicate());
            Element outRight = cryptoParam.pairing.pairing(Q_ID_i, X);
            if (outLeft.isEqual(outRight)){
                System.out.println("Key correctness and ownership check passed.");
                System.out.println("Base key extracted by user: "+K_ID_i);
                System.out.println("Computing main and ephemeral secret keys...");
                // Compute main and ephemeral secret keys.
                secretKeys[0] = K_ID_i.mulZn(u);
                Element t_p = cryptoParam.Zr.newRandomElement();
                String prepHash_3 = Integer.toString(T_D);
                hashFunc(t_p, prepHash_3);
                secretKeys[1] = secretKeys[0].mulZn(u.add(t_p));
                return secretKeys;
            } else {
                System.out.println("Key correctness and ownership check failed.");
                secretKeys[0].setToZero();
                secretKeys[1].setToZero();
                return secretKeys;
            }
        } else {
            System.out.println("Failed data assurance from EBKG and data integrity");
            secretKeys[0].setToZero();
            secretKeys[1].setToZero();
            return secretKeys;
        }
    }

    // ======================= Utility functions =======================
    public void printStatements() {
        System.out.println("============ Public Key Parameters ==============");
        System.out.println("Generator (g): " +cryptoParam.g);
        System.out.println("============== EBKG Parameters ===============");
        System.out.println("PRIVATE KEY OF EBKG x : "+x);
        System.out.println("PUBLIC KEY OF EBKG X : "+X);
        System.out.println("=================================================\n");
    }

    public void printDesigUserParams(ArrayList<specificUserParams> dUparams) {
        System.out.println("============ Specific user Public Channel Parameters ==============");
        System.out.println("V_ID_i: "+ dUparams.get(0).V_ID_i);
        System.out.println("s: "+ dUparams.get(0).s);
        System.out.println("e: "+ dUparams.get(0).e);
        System.out.println("v: "+ dUparams.get(0).v);
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


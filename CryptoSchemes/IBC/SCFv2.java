import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class SCFv2 {
    private cryptoParams cryptoParam;        // Public Key Parameters.
    private Element x;                      // Master Secret Key.
    public Element Q;                       // Master Public Key.
    private Element u;                      // For computing user secret key.
    private Element r;                      // For computing user secret key.

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

        // Set Master Public Key. Q = xG
        Q = (cryptoParam.g.duplicate()).mulZn(x);

        // Display public values.
        printStatements();
    }

    public Element setUserPubParam(String userID) throws NoSuchAlgorithmException{
        // r \in Zr, u=H(ID||r||Q)
        r = (cryptoParam.Zr.newRandomElement()).getImmutable();
        u = cryptoParam.Zr.newElement();
        String mergedData = userID + r + Q;
        hashFunc(u, mergedData);
        Element U = cryptoParam.G1.newElement();
        U = ((cryptoParam.g.duplicate()).mulZn(u)).getImmutable();
        System.out.println("User Public params set.");
        System.out.println("U: "+ U);
        return U;
    }

    public ArrayList<designatedUserParam> setDesigUserKey(String userID, Element U, int T_M) throws NoSuchAlgorithmException{
        // y \in Zr.
        // s = H(T_M||ID||y)
        // U_ID = y.U^{xs}
        // Initialise elements:
        designatedUserParam userSpecificParams = new designatedUserParam();
        Element Y = cryptoParam.G1.newRandomElement();
        System.out.println("Random Y value: "+ Y);
        userSpecificParams.s = cryptoParam.Zr.newElement();
        String mergedData = T_M + userID + Y;
        hashFunc(userSpecificParams.s, mergedData);
        userSpecificParams.U_ID = cryptoParam.G1.newElement();
        userSpecificParams.U_ID = (U.powZn(x.mulZn(userSpecificParams.s))).mul(Y);
        userSpecificParams.U = U;
        // Prepare arrayList for return statement.
        ArrayList<designatedUserParam> designatedUserPubParams = new ArrayList<>();
        designatedUserPubParams.add(userSpecificParams);
        // System.out.println("Designated user params published.");
        printDesigUserParams(designatedUserPubParams);
        return designatedUserPubParams;
    }

    public Element[] userKeyExtract(ArrayList<designatedUserParam> desigUserParam, String userID, int T_M, int T_D) throws NoSuchAlgorithmException{
        // y = U_ID * Q^{-us}
        Element Y = (Q.powZn(u.negate().mulZn(desigUserParam.get(0).s))).mul(desigUserParam.get(0).U_ID);
        System.out.println("Extracted Y value: "+ Y);
        // Verify correctness and ownership.
        Element sComputed = cryptoParam.Zr.newElement();
        String userDataMerged = T_M + userID + Y;
        hashFunc(sComputed, userDataMerged);
        if (sComputed.isEqual(desigUserParam.get(0).s)){
            System.out.println("Extracted Y value correct. Proceeding...");
            Element mainSk = cryptoParam.G1.newElement();
            mainSk = (Y.mulZn(r)).mul(desigUserParam.get(0).U_ID);
            // Compute Eph secret key.
            String mergedData =  Integer.toString(Q.getLengthInBytes()) + mainSk + T_D; // Check properly.
            Element v = cryptoParam.Zr.newElement();
            hashFunc(v, mergedData);
            Element EphKey = cryptoParam.G1.newElement();
            EphKey = (cryptoParam.g.duplicate()).mulZn(v);
            Element[] returnedVals = { mainSk, EphKey};
            System.out.println("User Key extraction done.");
            return returnedVals;
        } else {
            System.out.println("Corretness check failed. Execution aborted");
            Element mainSk = cryptoParam.G1.newElement().setToZero();
            Element[] returnedVals = { mainSk};
            return returnedVals;
        }
    }

    // ======================= Utilities Functions Below =======================
    public void printStatements() {
        System.out.println("============ Public Key Parameters ==============");
        System.out.println("G1: "+cryptoParam.G1);
        System.out.println("Gt: "+cryptoParam.Gt);
        System.out.println("Zr: "+cryptoParam.Zr);
        System.out.println("g: " +cryptoParam.g);
        System.out.println("============== PKG Parameters ===============");
        System.out.println("PRIVATE KEY OF PKG x : "+x);
        System.out.println("PUBLIC KEY OF PKG Q : "+Q);
        System.out.println("=================================================\n");
    }

    public void printDesigUserParams(ArrayList<designatedUserParam> dUparams) {
        System.out.println("============ Designated User Parameters ==============");
        System.out.println("U: "+ dUparams.get(0).U);
        System.out.println("U_ID: "+ dUparams.get(0).U_ID);
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

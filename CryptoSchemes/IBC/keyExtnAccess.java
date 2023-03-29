import it.unisa.dia.gas.jpbc.*;
// import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
//import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
//import it.unisa.dia.gas.jpbc.PairingParametersGenerator;

public class keyExtnAccess {
    private cryptoParams cryptoParam;        // Public Key Parameters.
    private Element x;                      // Master Secret Key.
    public Element Q;                       // Master Public Key.

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
    public int initTimeFrame(int T_M){// To be improved.
        // Require that Setup must have been run:
        if (cryptoParam == null && x.isZero()==true) {
            System.out.println("First execute Setup!");
            return 0;
        }
        return T_M;
    }

    public Element[] keyExtract(String userID, int T_M, int T_D) throws NoSuchAlgorithmException{
        // u_i = H_1(ID_i||T_M||T_D), mainSk = G^(x+u_i)
        // v = H_1(Q||mainSk||T_D), EphKey = v*G
        Element mainSk = cryptoParam.G1.newElement();
        Element EphKey = cryptoParam.G1.newElement();
        Element u_i = cryptoParam.Zr.newElement();
        Element v = cryptoParam.Zr.newElement();
        String mergedData_1 = userID + T_M + T_D;
        hashFunc(u_i, mergedData_1);
        computeMSK(mainSk,cryptoParam.g.duplicate(),x,u_i);
        String mergedData_2 =  Integer.toString(Q.getLengthInBytes()) + mainSk + T_D; // Check properly.
        hashFunc(v, mergedData_2);
        EphKey = (cryptoParam.g.duplicate()).mulZn(v);
        Element[] returnedVals = { mainSk, EphKey};
        System.out.println("Key extraction done.");
        return returnedVals;
    }

    public Element keyRenewal(Element mainSk, int T_M, int nextT_D) throws NoSuchAlgorithmException{
        Element EphKey = cryptoParam.G1.newRandomElement();
        EphKey.setToZero();
        if (nextT_D <= T_M){
            Element v = cryptoParam.Zr.newElement();
            String mergedData_2 =  Integer.toString(Q.getLengthInBytes()) + mainSk + nextT_D; // Check properly.
            hashFunc(v, mergedData_2);
            EphKey = (cryptoParam.g.duplicate()).mulZn(v);
            return EphKey;
        }else{
            EphKey.setToZero(); // Added for loop purposes.
            System.out.println("Sorry! Ephemeral secret key cannot be renewed: Time bound exceeded.");
            return EphKey;
        }
    }

    public Element keyAccess(Element mainSk, String userID, int prevT_D) throws NoSuchAlgorithmException{
        // Authentication of userID owing mainSk implicitly done.
        int T_M = prevT_D*2; // Highly abstracted.
        Element EphKey = cryptoParam.G1.newElement();
        Element u_i = cryptoParam.Zr.newElement();
        Element v = cryptoParam.Zr.newElement();
        String mergedData_1 = userID + T_M + prevT_D;
        hashFunc(u_i, mergedData_1);
        Element msk = cryptoParam.G1.newElement();
        computeMSK(msk,cryptoParam.g.duplicate(),x,u_i);
        if (mainSk.isEqual(msk)){
            System.out.println("Main Secret Key match.");
        }
        String mergedData_2 =  Integer.toString(Q.getLengthInBytes()) + msk + prevT_D; // Check properly.
        hashFunc(v, mergedData_2);
        EphKey = (cryptoParam.g.duplicate()).mulZn(v);
        System.out.println("Past Ephemeral Secret Key computed: "+ EphKey);
        return EphKey;
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

    private static void computeMSK(Element mainSk, Element g, Element x, Element u_i){
        mainSk.set(g.powZn(x.add(u_i)));
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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;
import it.unisa.dia.gas.jpbc.Element;

// import javax.swing.text.html.parser.Element;

public class P2P {

    private static List<Peer> peers = new ArrayList<>();
    private static int lastUsedPort = 4000;

    public static Peer addPeer(Blockchain blockchain) {
        Peer peer = new Peer(blockchain, lastUsedPort++);
        peers.add(peer);
        return peer;
    }
    
    public static void removePeer(int index) {
        Peer peer = peers.get(index);
        peer.stopServer();
        peers.remove(index);
    }

    public static void removePeer(Peer peer) {
        Iterator<Peer> iterator = peers.iterator();
        while (iterator.hasNext()) {
            if (iterator.next().equals(peer)) {
                peer.stopServer();
                iterator.remove();
                break;
            }
        }
    }
    
    public static void removeAllPeers() {
        Iterator<Peer> iterator = peers.iterator();
        while (iterator.hasNext()) {
            Peer peer = iterator.next();
            peer.stopServer();
            iterator.remove();
        }
    }
    
    public static Peer getPeer(int index) {
        return peers.get(index);
    }

    public static List<Peer> getPeers() {
        return peers;
    }
    
    public static void showPeers() {
        for (int i = 0; i < peers.size(); i++) {
            System.out.println("Peer " + (i + 1) + ": " + peers.get(i).getPort());
        }
    }

    public static void showPeersWithBlockchain() {
        for (int i = 0; i < peers.size(); i++) {
            System.out.println("Peer " + (i + 1) + " (" + peers.get(i).getPort() + "): " + peers.get(i).getBlockchain());
        }
    }

    /**
     * The main starting point of the blockchain demo. First, add some peers (option 1) and mine some data 
     * by using a particular peer (option 2).  Newly mined block is broadcast to all the peers.
     *
     * @param args
     */
    public static void main(String[] args) {
        try {
            int menuChoice;
            int blockDataType;
            String userIdentity;
            int peerIndex;
            Scanner s = new Scanner(System.in);
            Scanner blockChoice = new Scanner(System.in);
            Scanner userId = new Scanner(System.in);
            Blockchain blockchain = new Blockchain(new ArrayList<>(), 3);

            while (true) {

                System.out.println("\n======= Local Blockchain with Java =======");
                System.out.println("1. Add Peer");
                System.out.println("2. Mine data in peer");
                System.out.println("3. Remove peer");
                System.out.println("4. Show peers");
                System.out.println("5. Exit");

                menuChoice = s.nextInt();

                switch (menuChoice) {
                    case 1:
                        P2P.addPeer(blockchain);
                        System.out.println("New peer added!");
                        P2P.showPeersWithBlockchain();
                        break;
                    case 2:
                        System.out.println("Choose peer: (a number for ex. 1, 2, etc.)");
                        P2P.showPeers();
                        peerIndex = s.nextInt();
                        Peer p = P2P.getPeer(peerIndex - 1);
                        // Get user identity....more light ID of the peer.
                        System.out.println("Enter user ID: (No spaces)");
                        userIdentity = userId.next();
                        // Get choice of data for the blockchain.
                        System.out.println("Choose block data type: (User: 1, KGC:2 or Key retrieval: 3)");
                        blockDataType = blockChoice.nextInt();
                        switch (blockDataType) {
                            case 1:
                                System.out.println("Inside user block");
                                Element[] userData = blockchain.genUserData(userIdentity);
                                p.mine(userData);
                                System.out.println("Key request executed!");
                                P2P.showPeersWithBlockchain();
                                break;
                            case 2:
                                System.out.println("Inside KGC block");
                                Element[] keyData = blockchain.genKeyExtraction(userIdentity);
                                p.mine(keyData);
                                System.out.println("Key issuance executed!");
                                P2P.showPeersWithBlockchain();
                                break;
                            case 3:
                                System.out.println("Inside key retrieval block");
                                Element[] issuedKeyExtract = blockchain.extractIssuedKey(userIdentity);
                                p.mine(issuedKeyExtract);
                                System.out.println("============ Partial private key issued ==============");
                                System.out.println(issuedKeyExtract[1]);
                                System.out.println("=================================================\n");
                                System.out.println("Key retrieval completed!");
                                break;
                            default:
                                System.out.println("Wrong choice for block data type!");
                        }
                        break;
                    case 3:
                        System.out.println("Choose peer: (a number for ex. 1, 2, etc.)");
                        P2P.showPeers();
                        peerIndex = s.nextInt();
                        P2P.removePeer(peerIndex - 1);
                        System.out.println("Peer " + peerIndex + " removed!");
                        P2P.showPeersWithBlockchain();
                        break;
                    case 4:
                        P2P.showPeersWithBlockchain();
                        break;
                    case 5:
                        P2P.removeAllPeers();
                        System.out.println("Simulation terminated!");
                        System.exit(0);
                    default:
                        System.out.println("Wrong choice!");
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
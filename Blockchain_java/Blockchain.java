import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.List;
import java.util.ListIterator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.Element;

public class Blockchain {

    private List<Block> blocks;
    private int difficulty;
    private cryptoParams cryptoParam;     // Public Key Parameters.
    KeyIssuance KeyIssuance = new KeyIssuance();

    public void BCcryptoSetup(){
        // Setup must be run only once:
        if (cryptoParam != null) {
            System.out.println("Setup already executed!");
            return;
        }
        // Initialise Pairing and its Parameters:
        cryptoParam = new cryptoParams();
        cryptoParam.pairing = PairingFactory.getPairing("params.properties"); // Get parameters from file.
        // For ease of use. Returns random elements.
        cryptoParam.Zr = cryptoParam.pairing.getZr();
        System.out.println("Blockchain crypto setup executed!");
    }

    public Element[] genUserData(String ID) throws NoSuchAlgorithmException {
        Element[] data = KeyIssuance.setSecretValue(ID);
        return data;
    }

    public Element[] genKeyExtraction(String userID) throws NoSuchAlgorithmException {
        Element[] data = KeyIssuance.partialPrivateKeyExtract(userID);
        return data;
    }

    public Element[] extractIssuedKey(String userID) throws NoSuchAlgorithmException {
        Element[] data = KeyIssuance.keyExtraction(userID);
        return data;
    }

    public Blockchain(List<Block> blocks, int difficulty) {
        this.blocks = blocks;
        this.difficulty = difficulty;
        this.blocks.add(getGenesisBlock());
    }

    public List<Block> getBlocks() {
        return blocks;
    }

    public int getSize() {
        return blocks.size();
    }

    public Block getLatestBlock() {
        if (blocks.isEmpty()) return null;

        return blocks.get(blocks.size() - 1);
    }

    public void addBlock(Block block) {
        blocks.add(block);
    }

    /**
     * Mine, create a new block with the {@code data}, and finally, add it to the blockchain.
     * <p>
     * Mining is nothing but the process of calculating a hash of a {@link Block} with {@code data} such
     * that the hash starts with a specific number of zeros equal to the difficulty of the blockchain.
     *
     * @param data
     * @return
     */
    public Block mine(Element[] data) {
        Block previousBlock = getLatestBlock();
        Block nextBlock = getNextBlock(previousBlock, data);

        if (isValidNextBlock(previousBlock, nextBlock)) {
            blocks.add(nextBlock);
            return nextBlock;
        } else {
            throw new RuntimeException("Invalid block");
        }
    }

    /**
     * Executes the {@link Blockchain#isValidNextBlock(Block, Block)} on the entire blockchain.
     *
     * @return {@code false} if at least one block in the blockchain is invalid, {@code true} otherwise.
     */
    public boolean isValidChain() {
        ListIterator<Block> listIterator = blocks.listIterator();
        listIterator.next();
        while (listIterator.hasPrevious() && listIterator.hasNext()) {
            if (!isValidNextBlock(listIterator.previous(), listIterator.next())) {
                return false;
            }
        }
        return true;
    }

    /**
     * Creates the Genesis Block for the blockchain. The Genesis Block is the first block in the blockchain.
     *
     * @return the genesis block
     */
    private Block getGenesisBlock() {
        final long timestamp = new Date().getTime();
        int nonce = 0;
        BCcryptoSetup();
        Element[] data = {cryptoParam.Zr.newRandomElement()};
        // String data = "Data in Genesis Block";
        String hash;
        while (!isValidHashDifficulty(hash = calculateHashForBlock(0, "0", timestamp, data, nonce))) {
            nonce++;
        }

        return new Block(0, "0", timestamp, data, hash, nonce);
    }

    private Block getNextBlock(Block previousBlock, Element[] data) {
        // Signature check first.
        final int index = previousBlock.getIndex() + 1;
        final long timestamp = new Date().getTime();
        int nonce = 0;
        String hash;
        while (!isValidHashDifficulty(
                hash = calculateHashForBlock(index, previousBlock.getHash(), timestamp, data, nonce))) {
            nonce++;
        }
        return new Block(index, previousBlock.getHash(), timestamp, data, hash, nonce);
    }

    private boolean isValidNextBlock(Block previousBlock, Block nextBlock) {

        String nextBlockHash = calculateHashForBlock(nextBlock.getIndex(), previousBlock.getHash(),
                nextBlock.getTimestamp(), nextBlock.getData(), nextBlock.getNonce());

        if (previousBlock.getIndex() + 1 != nextBlock.getIndex()) {
            return false;
        } else if (!previousBlock.getHash().equals(nextBlock.getPreviousHash())) {
            return false;
        } else if (!this.isValidHashDifficulty(nextBlockHash)) {
            return false;
        } else if (!nextBlockHash.equals(nextBlock.getHash())) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * Checks if the hash respects the difficulty of the blockchain, i.e, if the hash
     * begins with a number of zeros equal to the difficulty of the blockchain.
     *
     * @param hash the SHA256 hash of the block.
     * @return {@code true} if hash obeys difficulty, {@code false} otherwise.
     */
    private boolean isValidHashDifficulty(String hash) {
        for (int i = 0; i < difficulty; i++) {
            if (hash.charAt(i) != '0') {
                return false;
            }
        }
        return true;
    }

    /**
     * Calculates the SHA256 hash of the block.
     *
     * @param index
     * @param previousHash
     * @param timestamp
     * @param data
     * @param nonce
     * @return the SHA256 hash of the block.
     */
    private String calculateHashForBlock(final int index, final String previousHash, final long timestamp,
                                         final Element[] data, final int nonce) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(
                    (index + previousHash + timestamp + data + nonce).getBytes(StandardCharsets.UTF_8));
            return bytesToHex(encodedhash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hashing Error: {}", e);
        }
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("Blockchain{");
        sb.append("blocks=").append(blocks);
        sb.append('}');
        return sb.toString();
    }
}
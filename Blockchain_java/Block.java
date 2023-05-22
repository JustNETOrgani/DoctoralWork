import java.io.Serializable;
import it.unisa.dia.gas.jpbc.Element;

/**
 * @author justnetorgani
 * @since 2023-04-10
 */
public class Block implements Serializable {
    
    private int index;
    private String previousHash;
    private long timestamp;
    Element[] data;
    private String hash;
    private int nonce;

    public Block(int index, String previousHash, long timestamp, Element[] data, String hash, int nonce) {
        this.index = index;
        this.previousHash = previousHash;
        this.timestamp = timestamp;
        this.data = data;
        this.hash = hash;
        this.nonce = nonce;
    }

    public int getIndex() {
        return index;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    public String getPreviousHash() {
        return previousHash;
    }

    public void setPreviousHash(String previousHash) {
        this.previousHash = previousHash;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public Element[] getData() {
        return data;
    }

    public void setData(Element[] data) {
        this.data = data;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public int getNonce() {
        return nonce;
    }

    public void setNonce(int nonce) {
        this.nonce = nonce;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("Block{");
        sb.append("index=").append(index);
        sb.append(", previousHash='").append(previousHash).append('\'');
        sb.append(", timestamp=").append(timestamp);
        sb.append(", data='").append(data).append('\'');
        sb.append(", hash='").append(hash).append('\'');
        sb.append(", nonce=").append(nonce);
        sb.append('}');
        return sb.toString();
    }
}
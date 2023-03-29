import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;

public class cryptoParams {
    public Pairing pairing;
    public Field G1, Gt, Zr;   // the field from pairing object
    public Element g;   // public element to act as generator.
}

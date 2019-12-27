package BGN;
import java.math.BigInteger;
/*
 * This source code uses the JPBC (Java Pairing-Based
 * Cryptography) library,
 * which can be downloaded from
 * http://gas.dia.unisa.it/projects/jpbc/
 */
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
/**
 * @ClassName: BGN
 * @Description: This is a sample java source code of BGN PKE.
 */
public class BGN {
    /**
     * @ClassName: PublicKey
     * @Description: This is a class for storing the
     * public key (n,G,GT,e,g,h) of BGN PKE.
     */
    public class PublicKey {
        private BigInteger n;
        private Field<Element> Field_G, Field_GT;
        private Pairing pairing;
        private Element g, h;
        public PublicKey(BigInteger n, Field<Element> G, Field<Element> GT, Pairing pairing, Element g,
                         Element h) {
            this.n = n;
            this.Field_G = G;
            this.Field_GT = GT;
            this.pairing = pairing;
            this.g = g;
            this.h = h;
        }
        public Element getG() {
            return g;
        }
        public Element getH() {
            return h;
        }
        public BigInteger getN() {
            return n;
        }
        public Pairing getPairing() {
            return pairing;
        }
        public Field<Element> getField_G() {
            return Field_G;
        }
        public Field<Element> getField_GT() {
            return Field_GT;
        }
    }
    /**
     * @ClassName: PrivateKey
     * @Description: This is a class for storing the
     * private key (p) of BGN PKE.
     */
    public class PrivateKey {
        private BigInteger p;
        public PrivateKey(BigInteger p) {
            this.p = p;
        }
        public BigInteger getP() {
            return p;
        }
    }
    private static final int T = 100; // The max range of message m
    private PublicKey pubkey;
    private PrivateKey prikey;
/**
 * @Title: keyGeneration
 * @Description: This function is responsible for
 * generating the public keys and the private keys.
 * @param k
 * the security parameter, which decides the
 * length of two large prime (p and q).
 * @return void
 */
public void keyGeneration(int k) {
    TypeA1CurveGenerator pg = new
            TypeA1CurveGenerator(2, k);
    PairingParameters pp = pg.generate();
    Pairing pairing = PairingFactory.getPairing(pp);
    BigInteger n = pp.getBigInteger("n");
    BigInteger q = pp.getBigInteger("n0");
    BigInteger p = pp.getBigInteger("n1");
    Field<Element> Field_G = pairing.getG1();
    Field<Element> Field_GT = pairing.getGT();
    Element g = Field_G.newRandomElement().getImmutable();
    Element h = g.pow(q).getImmutable();
    pubkey = new PublicKey(n, Field_G, Field_GT,
            pairing, g, h);
    prikey = new PrivateKey(p);
}
    /**
     * @Title: getPubkey
     * @Description: This function returns the public key of
     * BGN PKE.
     * @return PublicKey The public key used to encrypt
     * the data.
     */
    public PublicKey getPubkey() {
        return pubkey;
    }
    /**
     * @Title: getPrikey
     * @Description: This function returns the private key of
     * BGN PKE.
     * @return PrivateKey The private key used to decrypt
     * the data.
     */
    public PrivateKey getPrikey() {
        return prikey;
    }
/**
 * @Title: encrypt
 * @Description: This function is to encrypt the message
 * m, m in [0,1,2,...,T],
 * T=100 with public key.
 * @param m
 * The message
 * @param pubkey
 * The public key of BGN PKE.
 * @return Element The ciphertext.
 * @throws Exception
 * If the plaintext is not in [0,1,2,...,n],
 * there is an exception.
 */
public static Element encrypt(int m, PublicKey pubkey)
        throws Exception {
    if (m > T) {
        throw new Exception(
                "BGN.encrypt(int m, PublicKey pubkey): "
                        + "plaintext m is not in [0,1,2,...,"
                        + T + "]");
    }
    Pairing pairing = pubkey.getPairing();
    Element g = pubkey.getG();
    Element h = pubkey.getH();
    BigInteger r = pairing.getZr().newRandomElement()
            .toBigInteger();
    return g.pow(BigInteger.valueOf(m)).mul(h.pow(r))
            .getImmutable();
}
    /**
     *
     * @Title: decrypt
     * @Description: This function is to decrypt the ciphertext
     * with the public key and the private key.
     * @param c
     * The ciphertext.
     * @param pubkey
     * The public key of BGN PKE.
     * @param prikey
     * The private key of BGN PKE.
     * @return int The plaintext.
     * @throws Exception
     * If the plaintext is not in [0,1,2,...,n],
     * there is an exception.
     */
    public static int decrypt(Element c, PublicKey pubkey,
                              PrivateKey prikey) throws Exception {
        BigInteger p = prikey.getP();
        Element g = pubkey.getG();
        Element cp = c.pow(p).getImmutable();
        Element gp = g.pow(p).getImmutable();
        for (int i = 0; i <= T; i++) {
            if (gp.pow(BigInteger.valueOf(i)).isEqual(cp)) {
                return i;
            }
        }
        throw new Exception(
                "BGN.decrypt(Element c, PublicKey pubkey, PrivateKey prikey): "
                + "plaintext m is not in [0,1,2,...,"
                + T + "]");
    }
    public static int decrypt_mul2(Element c, PublicKey pubkey,
                                   PrivateKey prikey) throws Exception {
        BigInteger p = prikey.getP();
        Element g = pubkey.getG();
        Element cp = c.pow(p).getImmutable();
        Element egg = pubkey.getPairing().pairing(g, g).pow(p)
                .getImmutable();
        for (int i = 0; i <= T; i++) {
            if (egg.pow(BigInteger.valueOf(i)).isEqual(cp)) {
                return i;
            }
        }
        throw new Exception(
                "BGN.decrypt(Element c, PublicKey pubkey, PrivateKey prikey): "
                + "plaintext m is not in [0,1,2,...,"
                + T + "]");
    }
    /**
     * @Title: add
     * @Description: The function supports the homomorphic
     * addition with two ciphertext.
     * @param c1
     * The ciphertext.
     * @param c2
     * The ciphertext.
     * @parampubkey
     * The public key of BGN PKE.
     * @return Element The return value is c1*c2.
     */
    public static Element add(Element c1, Element c2) {
        return c1.mul(c2).getImmutable();
    }
/**
 * @Title: mul1
 * @Description: The function supports the homomorphic
 * multiplication with one ciphertext
 * and one plaintext.
 * @paramc
 * The ciphertext.
 * @paramm
 * The plaintext.
 * @parampubkey
 * The public key of BNG PKE.
 * @return Element The return value is c^m.
 */
public static Element mul1(Element c1, int m2) {
    return c1.pow(BigInteger.valueOf(m2)).getImmutable();
}
    /**
     * @Title: mul2
     * @Description: TODO
     * @param c1
     * The ciphertext.
     * @param c2
     * The ciphertext.
     * @param pubkey
     * The public key of BNG PKE.
     * @return Element The return value is e(c1,c2).
     */
    public static Element mul2(Element c1, Element c2,
                               PublicKey pubkey) {
        Pairing pairing = pubkey.getPairing();
        return pairing.pairing(c1, c2).getImmutable();
    }
    /**
     * @Title: selfBlind
     * @Description: The function supports the homomorphic
     * self-blinding with one ciphertext
     * and one random number.
     * @paramc
     * The ciphertext.
     * @paramr
     * A random number in Z_n.
     * @param pubkey
     * The public key of BNG PKE.
     * @return Element The return value is c1*h^r2.
     */
    public static Element selfBlind(Element c1, BigInteger r2,
                                    PublicKey pubkey) {
        Element h = pubkey.getH();
        return c1.mul(h.pow(r2)).getImmutable();
    }
    public static void main(String[] args) {
        BGN bgn = new BGN();
// Key Generation
        bgn.keyGeneration(512);
        BGN.PublicKey pubkey = bgn.getPubkey();
        BGN.PrivateKey prikey = bgn.getPrikey();
// Encryption and Decryption
        int m = 5;
        Element c = null;
        int decrypted_m = 0;
        try {
            c = BGN.encrypt(m, pubkey);
            decrypted_m = BGN.decrypt(c, pubkey, prikey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (decrypted_m == m) {
            System.out.println("Encryption and Decryption "
                    + "test successfully.");
        }
// Homomorphic Properties
// Addition
        int m1 = 5;
        int m2 = 6;
        try {
            Element c1 = BGN.encrypt(m1, pubkey);
            Element c2 = BGN.encrypt(m2, pubkey);
            Element c1mulc2 = BGN.add(c1, c2);
            int decrypted_c1mulc2 = BGN.decrypt(c1mulc2,
                    pubkey, prikey);
            if (decrypted_c1mulc2 == (m1 + m2)) {
                System.out.println("Homomorphic addition "
                        + "tests successfully.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
// multiplication-1
        m1 = 5;
        m2 = 6;
        try {
            Element c1 = BGN.encrypt(m1, pubkey);
            Element c1expm2 = BGN.mul1(c1, m2);
            int decrypted_c1expm2 = BGN.decrypt(c1expm2,
                    pubkey, prikey);
            if (decrypted_c1expm2 == (m1 * m2)) {
                System.out.println("Homomorphic multiplication-1 "
                                + "tests successfully.");
            }
        } catch (Exception e) {

            e.printStackTrace();
        }
// multiplication-2
        m1 = 5;
        m2 = 6;
        try {
            Element c1 = BGN.encrypt(m1, pubkey);
            Element c2 = BGN.encrypt(m2, pubkey);
            Element c1pairingc2 = pubkey.getPairing()
                    .pairing(c1, c2).getImmutable();
            int decrypted_c1pairingc2 =
                    BGN.decrypt_mul2(c1pairingc2, pubkey, prikey);
            if (decrypted_c1pairingc2 == (m1 * m2)) {
                System.out.println("Homomorphic multiplication-2 "
                                + "tests successfully.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
// self-Blinding
        m1 = 5;
        try {
            BigInteger r2 = pubkey.getPairing().getZr()
                    .newRandomElement().toBigInteger();
            Element c1 = BGN.encrypt(m1, pubkey);
            Element c1_selfblind = BGN.selfBlind(c1,
                    r2, pubkey);
            int decrypted_c1_selfblind =
                    BGN.decrypt(c1_selfblind, pubkey, prikey);
            if (decrypted_c1_selfblind == m1) {
                System.out.println("Homomorphic self-blinding "
                        + "tests successfully.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
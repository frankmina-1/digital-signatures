import java.io.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;

public class SignatureAssignment {
    /**
     * Loads filename into a byte array.
     * @param filename Name of file to be loaded
     * @return null on failure, or byte array on success
     */
    public byte[] loadFile(String filename) {
        byte[] data = null;
        FileInputStream fis = null;
        try {
            File f = new File(filename);
            fis = new FileInputStream(f);
            data = new byte[(int) f.length()];
            fis.read(data);
            fis.close();
        } catch (FileNotFoundException ex) {
            System.err.println("Unable to open "+filename);
            return null;
        } catch (IOException ex) {
            System.err.println("Unable to open "+filename);
            return null;
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (Exception e) {
                    // ignore
                }
            }
        }
        return data;
    }

    /**
     * Loads public key from filename
     * @param filename Name of file to be loaded
     * @return null on failure, or a PublicKey on success
     */
    public PublicKey loadKey(String filename) {
        byte[] data = loadFile(filename);
        if (data == null) {
            System.err.println("Unable to load key file.");
            return null;
        }
        X509EncodedKeySpec x509 = new X509EncodedKeySpec(data);
        PublicKey pub = null;
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pub = kf.generatePublic(x509);
        } catch (NoSuchAlgorithmException e) {
            System.err.println(e);
            return null;
        } catch (InvalidKeySpecException e) {
            System.err.println(e);
            return null;
        }
        return pub;
    }

    /**
     * Check if pdfFile was signed by keyFile, resulting in sigFile
     * @param keyFile File containing the DER-encoded key
     * @param sigFile File containing the signature
     * @param pdfFile File containing pdf
     * @return true of everything matches, false otherwise.
     */
    public boolean check(String keyFile, String sigFile, String pdfFile) {
        /* WRITE THIS CODE:
         *   1. load public key from file
         *     2. load signature from file
         *   3. Use Signature.getInstance() to get a new Signature object
         *  the signature was made as an RSA encoded SHA1 hash
         *     4. initialize the signature validation with the public key
         *     5. update the signature with the contents of the pdf
         *     6. check the signature
         */
        PublicKey p = loadKey(keyFile);
        byte[] sig = loadFile(sigFile);
        byte[] pdf = loadFile(pdfFile);
        Signature s;
        try
        {
            s = Signature.getInstance("SHA1withRSA");
            s.initVerify(p);
            s.update(pdf);
            return s.verify(sig);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return false;
    }

    public static void main(String[] args) {
        SignatureAssignment sigTester = new SignatureAssignment();
        //requires folders and signature.dat to be in the same directory
        File[] files = new File("keys").listFiles();
        File[] pdfFiles = new File("pdfs").listFiles();
        for(File pdfFile : pdfFiles)
        {
            if(!pdfFile.isDirectory()){
                if(pdfFile.getName().endsWith(".pdf")){
                    for(File file : files)
                    {
                        if(!file.isDirectory()){
                            if(file.getName().endsWith(".der"))
                            {
                                if(sigTester.check("keys/" + file.getName(), "signature.dat", "pdfs/" + pdfFile.getName()))
                                {
                                    System.out.println("Signature check verified!");
                                    System.out.println("public key file : " + file.getName());
                                    System.out.println("pdf file : " + pdfFile.getName());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    }
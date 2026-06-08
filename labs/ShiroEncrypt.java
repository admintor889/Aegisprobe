import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.util.ByteSource;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ShiroEncrypt {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: java -cp ... ShiroEncrypt <payload_file>");
            System.exit(1);
        }
        byte[] payload = Files.readAllBytes(Paths.get(args[0]));
        AesCipherService aes = new AesCipherService();
        byte[] key = Base64.decode(CodecSupport.toBytes("kPH+bIxk5D2deZiIxcaaaA=="));
        ByteSource ciphertext = aes.encrypt(payload, key);
        System.out.print(ciphertext.toBase64());
    }
}

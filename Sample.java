import java.io.File;

public class Sample extends Utility {

    public Sample(Editor e) {
        super(e);
        set_username_password();
    }

    @Override
    public void create(String file_name, String user_name, String password) throws Exception {
        dir = new File(file_name);

        dir.mkdirs();
        File meta = new File(dir, "0");
        String toWrite = "";
        toWrite = "0\n";  //length of the file
        toWrite += user_name;   //add username

        //padding
        while (toWrite.length() < Config.BLOCK_SIZE) {
            toWrite += '\0';
        }

        save_to_file(toWrite.getBytes(), meta);
        return;
    }

    @Override
    public String findUser(String file_name) throws Exception {
        File file = new File(file_name);
        File meta = new File(file, "0");
        String s = byteArray2String(read_from_file(meta));
        String[] strs = s.split("\n");
        return strs[1];
    }

    @Override
    public int length(String file_name, String password) throws Exception {
        File file = new File(file_name);
        File meta = new File(file, "0");
        String s = byteArray2String(read_from_file(meta));
        String[] strs = s.split("\n");
        return Integer.parseInt(strs[0]);
    }

    @Override
    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
        File root = new File(file_name);
        int file_length = length(file_name, password);
        if (starting_position + len > file_length) {
            throw new Exception();
        }

        int start_block = starting_position / Config.BLOCK_SIZE;

        int end_block = (starting_position + len) / Config.BLOCK_SIZE;

        String toReturn = "";

        for (int i = start_block + 1; i <= end_block + 1; i++) {
            String temp = byteArray2String(read_from_file(new File(root, Integer.toString(i))));
            if (i == end_block + 1) {
                temp = temp.substring(0, starting_position + len - end_block * Config.BLOCK_SIZE);
            }
            if (i == start_block + 1) {
                temp = temp.substring(starting_position - start_block * Config.BLOCK_SIZE);
            }
            toReturn += temp;
        }

        System.out.println(toReturn);
        return toReturn.getBytes("UTF-8");

    }

    @Override
    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
        String str_content = byteArray2String(content);
        File root = new File(file_name);
        int file_length = 0;


        int len = str_content.length();
        int num_blocks = (int) Math.ceil((double) content.length / Config.BLOCK_SIZE);


        int startBlock = starting_position / Config.BLOCK_SIZE;
        int end_block = (starting_position + content.length - 1) / Config.BLOCK_SIZE;


        for (int i = startBlock + 1; i <= end_block + 1; i++) {
            int sp = (i - 1) * Config.BLOCK_SIZE - starting_position;
            int ep = (i) * Config.BLOCK_SIZE - starting_position;
            String prefix = "";
            String postfix = "";
            if (i == startBlock + 1 && starting_position != startBlock * Config.BLOCK_SIZE) {

                prefix = byteArray2String(read_from_file(new File(root, Integer.toString(i))));
                prefix = prefix.substring(0, starting_position - startBlock * Config.BLOCK_SIZE);
                sp = Math.max(sp, 0);
            }

            if (i == end_block + 1) {
                File end = new File(root, Integer.toString(i));
                if (end.exists()) {

                    postfix = byteArray2String(read_from_file(new File(root, Integer.toString(i))));

                    if (postfix.length() > starting_position + len - end_block * Config.BLOCK_SIZE) {
                        postfix = postfix.substring(starting_position + len - end_block * Config.BLOCK_SIZE);
                    } else {
                        postfix = "";
                    }
                }
                ep = Math.min(ep, len);
            }

            String toWrite = prefix + str_content.substring(sp, ep) + postfix;

            while (toWrite.length() < Config.BLOCK_SIZE) {
                toWrite += '\0';
            }

            save_to_file(toWrite.getBytes(), new File(root, Integer.toString(i)));
        }


        //update meta data

        if (content.length + starting_position > length(file_name, password)) {
            String s = byteArray2String(read_from_file(new File(root, "0")));
            String[] strs = s.split("\n");
            strs[0] = Integer.toString(content.length + starting_position);
            String toWrite = "";
            for (String t : strs) {
                toWrite += t + "\n";
            }
            while (toWrite.length() < Config.BLOCK_SIZE) {
                toWrite += '\0';
            }
            save_to_file(toWrite.getBytes(), new File(root, "0"));

        }
    }

    @Override
    public boolean check_integrity(String file_name, String password) {
        return false;
    }

    @Override
    public void cut(String file_name, int len, String password) throws Exception {

        File root = new File(file_name);
        int file_length = length(file_name, password);

        if (len > file_length) {
            throw new Exception();
        }
        int end_block = (len) / Config.BLOCK_SIZE;

        File file = new File(root, Integer.toString(end_block + 1));
        String str = byteArray2String(read_from_file(file));
        str = str.substring(0, len - end_block * Config.BLOCK_SIZE);
        while (str.length() < Config.BLOCK_SIZE) {
            str += '\0';
        }

        save_to_file(str.getBytes(), file);

        int cur = end_block + 2;
        file = new File(root, Integer.toString(cur));
        while (file.exists()) {
            file.delete();
            cur++;
        }

        //update meta data
        String s = byteArray2String(read_from_file(new File(root, "0")));
        String[] strs = s.split("\n");
        strs[0] = Integer.toString(len);
        String toWrite = "";
        for (String t : strs) {
            toWrite += t + "\n";
        }
        while (toWrite.length() < Config.BLOCK_SIZE) {
            toWrite += '\0';
        }
        save_to_file(toWrite.getBytes(), new File(root, "0"));
    }


    private static String getContent(){
        String musk_bio = new String("Musk was born in Pretoria");
        String content = new String("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse ut sem nunc. Nulla facilisi. Nulla facilisi. Sed non malesuada tortor. Maecenas euismod euismod ipsum, vel feugiat quam. Morbi vestibulum placerat tellus vel feugiat. Nullam eget rutrum felis. Duis sed nibh pharetra, gravida neque nec, tempor magna. Sed ac risus non mauris elementum euismod. Donec dignissim, mauris vel hendrerit pharetra, sapien tortor mattis lectus, id dapibus turpis ipsum ut nunc. Aliquam erat volutpat. Sed iaculis neque ac lacus tincidunt faucibus. Donec vel nisi quis erat tincidunt sollicitudin vel vel odio. Vestibulum euismod diam in quam varius, nec iaculis orci consequat. Sed vel blandit tellus. Etiam a dolor libero. Fusce lobortis, elit in laoreet interdum, ante ante dictum magna, sit amet luctus quam sapien at ipsum. Sed bibendum lorem non massa malesuada, non consectetur eros faucibus. Nulla facilisi. Sed fermentum feugiat sapien, at efficitur velit volutpat vel. Duis bibendum est eu arcu tincidunt, nec scelerisque erat vehicula. In sit amet massa tristique, ultrices purus vel, imperdiet quam. Donec rutrum purus vel nibh aliquet, a luctus ipsum facilisis. Nulla fringilla est odio, in tincidunt ipsum congue id. Nulla facilisi. Sed vulputate aliquam nulla, eu mollis purus semper ac. Duis quis arcu euismod, consectetur dolor id, posuere quam. Nunc vel erat lectus. Donec volutpat erat elit, eu viverra nibh fermentum eu. Praesent in leo a sapien molestie maximus. Duis non imperdiet dolor. Nam vehicula auctor purus, eget cursus arcu cursus sed. Fusce maximus lectus non magna vehicula malesuada. Suspendisse malesuada diam eget nibh porttitor, vitae blandit ante varius. Duis varius fringilla nisl, vel feugiat sapien laoreet at. Sed in velit neque. Vestibulum suscipit blandit magna, a pellentesque nisl maximus vitae. Aenean commodo risus sed risus ultricies tristique a vel nisi. Sed commodo elit sit amet dolor aliquam venenatis. Praesent at bibendum urna. Etiam vel ex sed leo finibus venenatis. Sed sed ipsum sit amet elit rutrum suscipit vel vel elit. Nulla varius blandit leo, quis bibendum ante molestie sit amet. Donec id luctus lectus. Quisque rutrum felis at mi tincidunt posuere. Donec pretium mi eu sem dignissim fringilla. Morbi gravida lorem vel mauris auctor, eget eleifend nibh efficitur. Nulla facilisi. In hac habitasse platea dictumst. Suspendisse viverra justo at felis malesuada, vel mattis leo varius. Maecenas maximus augue ac bibendum aliquet. Vivamus sit amet purus ac arcu pulvinar egestas. Integer faucibus");
        return musk_bio;
    }

    public static void main(String[] args) {
        Editor edr = new Editor();
        Sample efs = new Sample(edr);
        try {
            efs.write("/Users/pritul/Books/Information security/Project1/src/my_file2",30,getContent().getBytes(),"macbook");
            efs.read("/Users/pritul/Books/Information security/Project1/src/my_file2",50,300,"macbook");
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }

    }
    
}

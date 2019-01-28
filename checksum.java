/*
 Michael Patellis
 11/4/2018
 Created for Michael McAlpin's Computer Security (CIS 3360) class.
 All the provided input key and plaintext files are his work.
 Code is my own.
 */

import java.io.*;

public class checksum
{
    private static final int BIT8_MAX = 256;
    private static final int BIT16_MAX = 65536;
    private static final long BIT32_MAX = 4294967296L;
    private static final int CHARS_PER_LINE = 80;
    private static final String PAD = "X";

    private static long bit8(String cs)
    {
        long checksum = 0;

        while (!(cs.equals("")))
        {
            checksum += cs.charAt(0);
            checksum = checksum%BIT8_MAX;
            cs = cs.substring(1);
        }
        return checksum;
    }

    private static long bit16(String cs)
    {
        long checksum = 0;
        long temp;

        while (!(cs.equals("")))
        {
            temp = cs.charAt(0) << 8;
            temp += cs.charAt(1);
            checksum += temp;
            checksum = checksum%BIT16_MAX;
            cs = cs.substring(2);
        }
        return checksum;
    }

    private static long bit32(String cs)
    {
        long checksum = 0;
        long temp;

        while(!(cs.equals("")))
        {
            temp = cs.charAt(0) << 24;
            temp += cs.charAt(1) << 16;
            temp += cs.charAt(2) << 8;
            temp += cs.charAt(3);
            checksum += temp;
            checksum = checksum%BIT32_MAX;
            cs = cs.substring(4);
        }
        return checksum;
    }

    private static long checksum(String cs, int bit)
    {
        long retVal;

        if (bit == 8)
            retVal = bit8(cs);
        else if (bit == 16)
            retVal = bit16(cs);
        else if (bit == 32)
            retVal = bit32(cs);
        else
            retVal = -1;

        return retVal;
    }

    private static void printOutput(String text)
    {
        int i;
        int loopCon = text.length()/CHARS_PER_LINE;
        String print = "";
        System.out.println();

        for (i = 1; i <= loopCon; i++)
        {
            print = text.substring(0, CHARS_PER_LINE);
            System.out.println(print);
            text = text.substring(CHARS_PER_LINE);
        }
        System.out.println(text);
    }

    private static String readFile(String file, int bit)
    {
        String error = "Error";
        try
        {
            String retVal = "";
            char input;
            int temp, i, loopCon;
            BufferedReader in = new BufferedReader(new FileReader(file));

            while ((temp = in.read()) != -1)
            {
                input = (char) temp;
                retVal = retVal + input;
            }
            in.close();

            if (bit == 16 && retVal.length()%2 == 1)
                retVal = retVal + PAD;
            else if (bit == 32 && (loopCon = retVal.length()%4) != 0)
            {
                loopCon = 4 - loopCon;
                for (i = 0; i < loopCon; i++)
                    retVal = retVal + PAD;
            }
            return retVal;
        } catch (FileNotFoundException e1)
        {
            System.out.println("File not found exception");
            return error;
        } catch (IOException e2)
        {
            System.out.println("IOException");
            return error;
        }
    }


    public static void main(String[] args)
    {
        String iFile, checksumSize, checksum;
        int csSize;
        long csVal;

        iFile = args[0];
        checksumSize = args[1];
        csSize = Integer.parseInt(checksumSize);

        if (!(csSize == 8 || csSize == 16 || csSize == 32))
        {
            System.err.print("Valid checksum sizes are 8, 16, or 32\n");
            return;
        }

        checksum = readFile(iFile, csSize);

        printOutput(checksum);

        csVal = checksum(checksum, csSize);

        System.out.printf("%2d bit checksum is %8x for all %4d chars\n", csSize, csVal, checksum.length());
    }
}

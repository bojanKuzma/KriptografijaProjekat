package org.unibl.etf;

public class Utils {
    private static final int MIN = 1;
    public static int getRandomNumber(int max) {
        return (int) ((Math.random() * (max - MIN)) + MIN);
    }
}

package org.tsicoop.dpdpcms.framework;

import java.util.Arrays;

public class RecoUtil {

    private static int NUM_DIMENSIONS = 500;

    public static String vectorToString(double[] vector) {
        return "[" + String.join(",", Arrays.stream(vector)
                .mapToObj(String::valueOf)
                .toArray(String[]::new)) + "]";
    }

    public static double[] calculateVector(String[] masterList, String[] userList) {
        double[] vector = new double[NUM_DIMENSIONS];
        if(userList != null) {
            for (int i = 0; i < masterList.length; i++) {
                vector[i] = result(userList, masterList[i]);
            }
        }
        return vector;
    }

    public static String[] addString(String[] array, String newString) {
        if (array == null) {
            return new String[] {newString}; // Handle the case of a null array
        }

        String[] newArray = Arrays.copyOf(array, array.length + 1);
        newArray[newArray.length - 1] = newString;
        return newArray;
    }

    public static void printStringArray(String[] array) {
        if (array == null) {
            System.out.println("null"); // Or handle null as you prefer
            return;
        }
        System.out.println(Arrays.toString(array)); // Using Arrays.toString() is the most concise way.
    }

    public static double result(String[] list, String attribute){
        double result = 0.0;
        String attributeM = null;
        for(int i=0;i< list.length;i++){
            attributeM = list[i];
            //System.out.println(attributeM);
            if(attributeM != null && attributeM.equalsIgnoreCase(attribute)) {
                result = 1.0;
                //System.out.println(result);
                break;
            }
        }
        return result;
    }

    public static boolean anyMatch(String[] input, String[] output){
        boolean match = false;
        for(int i=0;i<input.length;i++){
            for(int j=0;j<output.length;j++){
                if(input[i].equalsIgnoreCase(output[j])){
                    match = true;
                    break;
                }
            }
        }
        return match;
    }
}

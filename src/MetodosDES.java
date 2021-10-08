
import java.io.FileInputStream;
import java.io.FileOutputStream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author sofo9
 */
public class MetodosDES {
    

    public static boolean keyIsValida(String key){
        boolean r = false;
        
        //verifico el tamano del String
        if(key.length() == 8){
            
            byte[] bytes = key.getBytes();
            
            //verifico el tamano del String en Bytes, si se necesita 56 bits, y 8 bits es un Byte
            //entonces la llave medira 56/8=7 Bytes
            if(bytes.length == 7) r = true;
        }
        return r;
    }
    
    public byte[] cifrar(String key, String dirrecion) throws Exception{
        
        
        SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
        DESKeySpec kspec = new DESKeySpec(key.getBytes());
        SecretKey subllave = skf.generateSecret(kspec);
        Cipher cifrado = Cipher.getInstance("DES/ECB/PKCS5Padding");
         
        cifrado.init(Cipher.ENCRYPT_MODE, subllave);
        
        
        //leer el archivo y tener el buffer para la lectura, el tamaño y que entre en un bucle hasta
        //terminar de leer el tamño del archivo
        
        //el archivo o fichero lo transformamos a bits y hay que leerlo y cifrarlo o descifrarlo
        
        byte[] buffer = new byte[1000]; //quiero ir leyendo de 1000 en 1000 bits del fichero
        
        byte[] bufferCifrado; //aqui voy almacenar el resultado
        
        
        FileInputStream in = new FileInputStream(dirrecion);
        
        //Le quito el .txt 
        dirrecion = dirrecion.substring(0, dirrecion.length() - 4);
        
        FileOutputStream out = new FileOutputStream(dirrecion+".cifrado");
        
        
        int bytesleidos = in.read(buffer, 0, 1000);
        while(bytesleidos != -1){
            //mientras no se llegue al final del archivo o fichero
            bufferCifrado = cifrado.update(buffer, 0, bytesleidos);
            //para el texto claro leer y enviarlo al buffer cifrado
            out.write(bufferCifrado);
            //escribir el archivo cifrado
            bytesleidos = in.read(buffer, 0, 1000);
        }
        //acompletar el fichero o archivo con el cifrado
        bufferCifrado = cifrado.doFinal();
        out.write(bufferCifrado); //escribir el final del texto cifrado si lo hay
        
        in.close();
        out.close();
        
        return bufferCifrado;
        
        
    }
    
    public byte[] descifrar(String key, String dirrecion) throws Exception{
        
        SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
        DESKeySpec kspec = new DESKeySpec(key.getBytes());
        SecretKey subllave = skf.generateSecret(kspec);
        Cipher cifrado = Cipher.getInstance("DES/ECB/PKCS5Padding");
        
        
         //leer el archivo y tener el buffer para la lectura, el tamaño y que entre en un bucle hasta
        //terminar de leer el tamño del archivo
        
        //el archivo o fichero lo transformamos a bits y hay que leerlo y cifrarlo o descifrarlo
        
        byte[] buffer = new byte[1000]; //quiero ir leyendo de 1000 en 1000 bits del fichero
        
        byte[] bufferCifrado; //aqui voy almacenar el resultado
        
        
        FileInputStream in = new FileInputStream(dirrecion);
        
         //Le quito el .cifrado
        dirrecion = dirrecion.substring(0, dirrecion.length() - 8);
        FileOutputStream out = new FileOutputStream(dirrecion + ".descifrado");
        
        //vamos a descifrar
        cifrado.init(Cipher.DECRYPT_MODE, subllave);
        
        byte[] bufferPlano; //aqui voy almacenar el resultado descifrado
        
        
        
        int bytesleidos = in.read(buffer, 0, 1000);
        while(bytesleidos != -1){
            //mientras no se llegue al final del archivo o fichero
            bufferPlano = cifrado.update(buffer, 0, bytesleidos);
            //para el texto claro leer y enviarlo al buffer cifrado
            out.write(bufferPlano);
            //escribir el archivo cifrado
            bytesleidos = in.read(buffer, 0, 1000);
        }
        //acompletar el fichero o archivo con el descifrado
        bufferPlano = cifrado.doFinal();
        out.write(bufferPlano); //escribir el final del texto descifrado si lo hay
        
        in.close();
        out.close();
        
        return bufferPlano;
        
        
    }
}

Dolos is a tool aimed to support pentesters or security engineers when bypassing certificate pinning implemented on Android apps. 
It's built on top of the Soot framework (http://soot-oss.github.io/soot/) and leverages code instrumentation to check all application methods to detect the method responsible for validating the certificates. 
The detection is based on regex signatures derived from OkHttp3/4 implementations. Dolos patches the APK and inserts a print statement on the patched method.

To compile Dolos, use Maven with the following command:

**mvn clean compile assembly:single**
 
After compilation you can execute Dolos with the following command (Java 11):

**java -cp ~/Documents/Code/Overcome/Dolos/target/Dolos-1.0-jar-with-dependencies.jar com.poc.soot.dolos.App -a ./<APK>.apk -o ./outputDir**

It's worth to note that Dolos doesn't remove anti-tampering checks. This is a work in progress due to lack of enough signatures so if you have APKs with anti-tamper examples feel free to ping me.

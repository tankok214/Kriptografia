set keytoolCmd=keytool

"%keytoolCmd%" -genkeypair -alias mitm -keyalg RSA -keysize 2048 -keystore mitm_keystore.jks -validity 365 -dname "CN=*.bnr.ro, O=Banca Nationala a Romaniei, L=Bucuresti, ST=Bucuresti, C=RO" -ext "SAN=dns:*.bnr.ro,dns:bnr.ro" -storepass mitm123 -keypass mitm123


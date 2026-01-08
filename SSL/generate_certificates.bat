@echo off
REM SSL/TLS Certificate Generation Script
REM Creates CA hierarchy and certificates for Mutual TLS

setlocal enabledelayedexpansion

set identifier=tankok214
if not "%1"=="" set identifier=%1

echo.
echo === SSL/TLS Certificate Generation ===
echo Identifier: %identifier%
echo Hostname: %COMPUTERNAME%
echo.

REM Find keytool
set keytool=keytool
if defined JAVA_HOME (
    set keytool=%JAVA_HOME%\bin\keytool.exe
)

REM Create certificates directory
set certDir=certificates
if not exist %certDir% mkdir %certDir%
cd %certDir%

REM 1. RootCA (EC 256-bit)
echo [1/7] Creating RootCA...
openssl ecparam -genkey -name prime256v1 -out rootca_key.pem 2>nul
openssl req -new -x509 -days 90 -key rootca_key.pem -out rootca_cert.pem -subj "/C=RO/ST=Kolozs/L=Kolozsvar/O=BBTE/CN=%identifier%-RootCA" 2>nul
echo   Done

REM 2. ClientCA (EC 256-bit)
echo [2/7] Creating ClientCA...
openssl ecparam -genkey -name prime256v1 -out clientca_key.pem 2>nul
openssl req -new -key clientca_key.pem -out clientca.csr -subj "/C=RO/ST=Kolozs/L=Kolozsvar/O=BBTE/CN=%identifier%-ClientCA" 2>nul
openssl x509 -req -days 90 -in clientca.csr -CA rootca_cert.pem -CAkey rootca_key.pem -CAcreateserial -out clientca_cert.pem -extensions v3_ca 2>nul
echo   Done

REM 3. ServerCA (EC 256-bit)
echo [3/7] Creating ServerCA...
openssl ecparam -genkey -name prime256v1 -out serverca_key.pem 2>nul
openssl req -new -key serverca_key.pem -out serverca.csr -subj "/C=RO/ST=Kolozs/L=Kolozsvar/O=BBTE/CN=%identifier%-ServerCA" 2>nul
openssl x509 -req -days 90 -in serverca.csr -CA rootca_cert.pem -CAkey rootca_key.pem -CAcreateserial -out serverca_cert.pem -extensions v3_ca 2>nul
echo   Done

REM 4. Client Certificate (EC 256-bit) with FULL CHAIN
echo [4/7] Creating Client Certificate with full chain...
openssl ecparam -genkey -name prime256v1 -out client_key.pem 2>nul
openssl req -new -key client_key.pem -out client.csr -subj "/C=RO/ST=Kolozs/L=Kolozsvar/O=BBTE/CN=%identifier%-client" 2>nul
openssl x509 -req -days 90 -in client.csr -CA clientca_cert.pem -CAkey clientca_key.pem -CAcreateserial -out client_cert.pem 2>nul

REM Create complete certificate chain file (client + ClientCA + RootCA)
echo   Building full certificate chain...
copy /b client_cert.pem + clientca_cert.pem + rootca_cert.pem client_chain.pem >nul

REM Create PKCS12 with full chain
openssl pkcs12 -export -in client_chain.pem -inkey client_key.pem -out client.p12 -name client -passout pass:client123 2>nul

REM Convert to JKS
"%keytool%" -importkeystore -srckeystore client.p12 -srcstoretype PKCS12 -srcstorepass client123 -destkeystore client_keystore.jks -deststoretype JKS -deststorepass client123 -noprompt 2>nul
copy /y client_keystore.jks ..\ >nul
echo   Done - client_keystore.jks created with FULL CHAIN

REM 5. Server Certificate (RSA 2048-bit) with FULL CHAIN
echo [5/7] Creating Server Certificate with full chain...

REM Create OpenSSL config for SAN
(
echo [req]
echo distinguished_name = req_distinguished_name
echo req_extensions = v3_req
echo.
echo [req_distinguished_name]
echo.
echo [v3_req]
echo subjectAltName = @alt_names
echo.
echo [alt_names]
echo DNS.1 = localhost
echo DNS.2 = %COMPUTERNAME%
echo IP.1 = 127.0.0.1
) > san.cnf

REM Generate server certificate
openssl genrsa -out server_key.pem 2048 2>nul
openssl req -new -key server_key.pem -out server.csr -subj "/C=RO/ST=Kolozs/L=Kolozsvar/O=BBTE/CN=%COMPUTERNAME%" -config san.cnf -extensions v3_req 2>nul
openssl x509 -req -days 90 -in server.csr -CA serverca_cert.pem -CAkey serverca_key.pem -CAcreateserial -out server_cert.pem -extfile san.cnf -extensions v3_req 2>nul

REM Create complete certificate chain file (server + ServerCA + RootCA)
echo   Building full certificate chain...
copy /b server_cert.pem + serverca_cert.pem + rootca_cert.pem server_chain.pem >nul

REM Create PKCS12 with full chain
openssl pkcs12 -export -in server_chain.pem -inkey server_key.pem -out server.p12 -name server -passout pass:server123 2>nul

REM Convert to JKS
"%keytool%" -importkeystore -srckeystore server.p12 -srcstoretype PKCS12 -srcstorepass server123 -destkeystore server_keystore.jks -deststoretype JKS -deststorepass server123 -noprompt 2>nul
copy /y server_keystore.jks ..\ >nul
echo   Done - server_keystore.jks created with FULL CHAIN (CN=%COMPUTERNAME%, SAN=localhost,%COMPUTERNAME%)

REM 6. Client Truststore
echo [6/7] Creating Client Truststore...
"%keytool%" -import -trustcacerts -alias rootca -file rootca_cert.pem -keystore client_truststore.jks -storepass client123 -noprompt 2>nul
"%keytool%" -import -trustcacerts -alias serverca -file serverca_cert.pem -keystore client_truststore.jks -storepass client123 -noprompt 2>nul
copy /y client_truststore.jks ..\ >nul
echo   Done - client_truststore.jks created

REM 7. Server Truststore
echo [7/7] Creating Server Truststore...
"%keytool%" -import -trustcacerts -alias rootca -file rootca_cert.pem -keystore server_truststore.jks -storepass server123 -noprompt 2>nul
"%keytool%" -import -trustcacerts -alias clientca -file clientca_cert.pem -keystore server_truststore.jks -storepass server123 -noprompt 2>nul
copy /y server_truststore.jks ..\ >nul
echo   Done - server_truststore.jks created

REM Verification
echo.
echo === Verification ===
openssl verify -CAfile rootca_cert.pem -untrusted clientca_cert.pem client_cert.pem 2>nul | find "OK" >nul
if %errorlevel%==0 (
    echo Client cert chain: OK
) else (
    echo Client cert chain: FAILED
)

openssl verify -CAfile rootca_cert.pem -untrusted serverca_cert.pem server_cert.pem 2>nul | find "OK" >nul
if %errorlevel%==0 (
    echo Server cert chain: OK
) else (
    echo Server cert chain: FAILED
)

cd ..

echo.
echo === Complete! ===
echo Generated keystores:
dir /b *.jks 2>nul
echo.
echo Passwords: client123 / server123
echo.
echo Next: java MutualTLSServer (terminal 1)
echo       java MutualTLSClient https://localhost:8443/ (terminal 2)
echo.

endlocal

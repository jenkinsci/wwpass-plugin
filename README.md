WWPass Authentication Plugin for Jenkins CI
==============================================
Plugin for Jenkins CI, which implements authentucation via WWPass Keyset.



### Installing the plugin
=========================
* Installing from Jenkins CI repo:

  Go to **Manage Jenkins>Manage Plugins>Availiable** and search for "WWPass Authentication Plugin", check it and push the on of the install buttons (for your choice).
  

* Build plugin from source:

  After cloning the repo jenkins-wwpass-auth, use Maven to make HPI package:
    cd to folder there you put downloaded sources and run command:
  
    ```
    mvn package -DskipTests
    ```
    
  Go to **Manage Jenkins>Manage Plugins>Advanced** and upload recently generated .HPI file from *{sources}/target*.

  
### Setup plugin:
=================
First, you need to register on https://developers.wwpass.com/ and get Service Provider's personal certificate and key pair.

By default plugin searching certificate-key pair on the paths:

|                  |         Windows         |             Linux            |
|:----------------:|:-----------------------:|:----------------------------:|
| Certificate file | C:/wwpass/wwpass_sp.crt | /etc/ssl/certs/wwpass_sp.crt | 
|     Key file     | C:/wwpass/wwpass_sp.key | /etc/ssl/certs/wwpass_sp.key |

You may use this paths and names. If you want to use another path and names for this files, change it in Jenkins settins (if you are using WWPass authentication as a secondary realm, change these properties in **Manage Jenkins>Configure System**, or is you are using it as primary realm - in **Manage Jenkins>Configure Global Security**).

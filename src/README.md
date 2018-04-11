# HDS-SEC

### Prerequisites

Create database and user

```
create database AccountData;
use AccountData;
CREATE USER root IDENTIFIED BY 'root';
grant usage on *.* to root@localhost identified by 'root';
grant all privileges on AccountData.* to root@localhost;

javac *.java

java -cp "mysql-connector-java-5.1.46.jar:." Server

java ClientLibrary localhost

```
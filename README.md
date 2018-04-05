# HDS-SEC

### Prerequisites

Create database and user

```
create database accountdata;
use accountdata;
CREATE USER root IDENTIFIED BY 'root';
grant usage on *.* to root@localhost identified by 'root';
grant all privileges on accountdata.* to root@localhost;

```
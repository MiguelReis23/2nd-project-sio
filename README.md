## Description

This project was developed for the course of Information And Organisational Security (SIO) and the goal was to present a web application that would be an online shop to sell DETI memorabilia,
The purpose of this delivery was to work upon the first delivery of the project, improving the security of the application and adding new features.

## Authors

- GABRIEL JANICAS DA SILVA **108689**<br>
- MARTIM HENRIQUES CARVALHO **108749**<br>
- MIGUEL ROSA REIS **108545**<br>
- RODRIGO MIGUEL BARROS MOÇO **108939**<br>


## Key Issues

- 2.1.2 

- 2.1.7 

- 2.1.8 

- 2.2.1 

- 2.2.3 

- 3.2.3 e 3.4.X 

- 3.3.2 

- 4.2.2 e 13.2.3 

- 4.3.1 

- 5.3.6 

- 8.3.2 

- 11.1.4 

- 14.2.3 

## Features

From the list of software features given by the teacher, we implemented the following:

- Password strength evaluation, requiring at least 12 characters and at most 128 according to v2.1 of the ASVS and breach verification with resource of Have I Been Pwned API.

-Multi-factor authentication impemented with TOTP (Time-based One-Time Password) to authorize access to the application.

-Encryption of sensitive data in the database including passwords and the key used to generate the TOTP.


## RUN

1. Create the virtual environment:
```bash
python3 -m venv venv
```
2. Activate the virtual environment (Every time you open a new terminal you need to do this to make the virtual environment the default Python interpreter of this shell):
```bash
source venv/bin/activate
```
or (Windows):
```bash
.\venv\Scripts\activate.ps1
```

3. Install the requirements:
```bash
pip install -r requirements.txt
```

4. Run the application:


```bash
./run.sh app_org <PORT>
```
or:
```bash
./run.sh app_sec <PORT>
```

&emsp;&emsp;In Windows use instead:

```bash
.\run.bat app_org <PORT>
```
or:
```bash
.\run.bat app_sec <PORT>
```
5. Access the website:

```bash
http://127.0.0.1:<PORT>
```

6. To generate the database you need to access the following link:

```bash
/generate/all
```